package com.wangzi5151.luanyucipher.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 乱语 Luanyu v1/v2 — 认证加密方案。
 *
 * 基础模式 (v1, 单密钥):
 *   dk   = PBKDF2-HMAC-SHA256(密钥, salt, 600000) -> 256bit
 *   帧头 = 'L' 'Y' 0x01 | salt(16)
 *
 * 高级模式 (v2, 多密钥 1..10 把, 顺序敏感, 层层加锁):
 *   K1   = PBKDF2-HMAC-SHA256(密钥1, salt, 600000)
 *   Ki   = PBKDF2-HMAC-SHA256(密钥i, K(i-1)||salt, 600000)   i=2..n
 *   dk   = Kn
 *   帧头 = 'L' 'Y' 0x02 | n(1) | salt(16)
 *
 * 两者共同:
 *   密文 = AES-256-GCM(dk, iv=random12B, AAD=帧头, UTF-8(原文)) -> 含 128bit 认证标签
 *   输出 = 64 符号乱序字母表编码(3字节->4字符, 无填充)
 *
 * 无密钥校验位: 不嵌入任何可快速验证密钥的字段,
 * 攻击者在不知道原文任何片段时无法验证密钥猜测。
 */
public final class CryptoCore {

    public static final int VERSION1 = 0x01;
    public static final int VERSION2 = 0x02;
    public static final int PBKDF2_ITERATIONS = 600_000;
    public static final int MIN_PASSPHRASE_CHARS = 6;      // 基础模式(单密钥)
    public static final int MIN_ADV_PASSPHRASE_CHARS = 4;  // 高级模式每把密钥
    public static final int MAX_KEYS = 10;
    public static final int SALT_LEN = 16;
    public static final int IV_LEN = 12;
    public static final int TAG_LEN_BITS = 128;
    public static final int KEY_LEN_BYTES = 32;
    public static final int V1_HEADER_LEN = 3 + SALT_LEN;  // L Y ver salt
    public static final int V2_HEADER_LEN = 4 + SALT_LEN;  // L Y ver n salt

    private static final byte MAGIC0 = 'L';
    private static final byte MAGIC1 = 'Y';
    private static final int MIN_FRAME_LEN = V1_HEADER_LEN + IV_LEN + TAG_LEN_BITS / 8;

    /** 乱序字母表: 26小写 + 26大写 + 10数字 + '@' '#', 共64符号, 顺序固定且两端一致。 */
    static final String ALPHABET = "Y1W8U9JArCv3oKcpfMkSX4Py250b#LdBnVZHjGTmNOIwiaqsDQl6tgRxz@7ehuFE";

    static final int[] DECODE_MAP = new int[128];

    static {
        Arrays.fill(DECODE_MAP, -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            DECODE_MAP[ALPHABET.charAt(i)] = i;
        }
    }

    private CryptoCore() {
    }

    /** 解密/格式失败时抛出, message 为可直接展示给用户的中文。 */
    public static class LuanyuException extends Exception {
        public LuanyuException(String msg) {
            super(msg);
        }

        public LuanyuException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    // ============================================================ 加密 (基础 v1)

    public static String encrypt(String passphrase, String plaintext) throws LuanyuException {
        String key = normalize(passphrase);
        if (key.length() < MIN_PASSPHRASE_CHARS) {
            throw new LuanyuException("密钥太短：至少需要 " + MIN_PASSPHRASE_CHARS
                    + " 位数字或字母（当前 " + key.length() + " 位）");
        }
        return seal(new String[]{key}, plaintext, VERSION1, 1);
    }

    // ============================================================ 加密 (高级 v2)

    /**
     * 多密钥加密: 1..10 把密钥, 顺序敏感, 层层链式推导。
     * 每把密钥至少 {@link #MIN_ADV_PASSPHRASE_CHARS} 位。
     */
    public static String encryptMulti(String[] rawKeys, String plaintext) throws LuanyuException {
        String[] keys = validateMultiKeys(rawKeys);
        return seal(keys, plaintext, VERSION2, keys.length);
    }

    private static String seal(String[] keys, String plaintext, int version, int n)
            throws LuanyuException {
        if (plaintext == null) {
            throw new LuanyuException("原文不能为空");
        }
        try {
            SecureRandom rng = new SecureRandom();
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(salt);
            rng.nextBytes(iv);

            byte[] header = buildHeader(version, n, salt);
            byte[] dk = version == VERSION1
                    ? deriveKey(keys[0], salt)
                    : deriveKeyMulti(keys, salt);

            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dk, "AES"),
                    new GCMParameterSpec(TAG_LEN_BITS, iv));
            gcm.updateAAD(header);
            byte[] ct = gcm.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Arrays.fill(dk, (byte) 0);

            byte[] frame = new byte[header.length + IV_LEN + ct.length];
            System.arraycopy(header, 0, frame, 0, header.length);
            System.arraycopy(iv, 0, frame, header.length, IV_LEN);
            System.arraycopy(ct, 0, frame, header.length + IV_LEN, ct.length);
            return encode(frame);
        } catch (GeneralSecurityException e) {
            throw new LuanyuException("加密失败: " + e.getMessage(), e);
        }
    }

    // ============================================================ 解密

    /** 基础模式解密: 单密钥, 密钥至少 6 位; 自动识别 v1/v2 乱语。 */
    public static String decrypt(String passphrase, String garbledText) throws LuanyuException {
        String key = normalize(passphrase);
        if (key.length() < MIN_PASSPHRASE_CHARS) {
            throw new LuanyuException("密钥太短：至少需要 " + MIN_PASSPHRASE_CHARS
                    + " 位数字或字母（当前 " + key.length() + " 位）");
        }
        return open(new String[]{key}, garbledText);
    }

    /** 高级模式解密: 多密钥(1..10 把, 顺序与加密一致); 自动识别 v1/v2 乱语。 */
    public static String decryptMulti(String[] rawKeys, String garbledText) throws LuanyuException {
        String[] keys = validateMultiKeys(rawKeys);
        return open(keys, garbledText);
    }

    private static String open(String[] keys, String garbledText) throws LuanyuException {
        if (garbledText == null || garbledText.isEmpty()) {
            throw new LuanyuException("请先粘贴收到的乱语");
        }
        byte[] frame = decode(garbledText);
        if (frame.length < MIN_FRAME_LEN) {
            throw new LuanyuException("不是有效的乱语文本（内容过短或已损坏）");
        }
        if (frame[0] != MAGIC0 || frame[1] != MAGIC1) {
            throw new LuanyuException("不是有效的乱语文本（请确认完整粘贴，未被截断或改写）");
        }
        int ver = frame[2] & 0xFF;
        int headerLen;
        byte[] salt;

        if (ver == VERSION1) {
            if (keys.length != 1) {
                throw new LuanyuException("这串乱语是基础模式（1 把密钥）加密的，你提供了 "
                        + keys.length + " 把 — 请切换到基础模式");
            }
            if (keys[0].length() < MIN_PASSPHRASE_CHARS) {
                throw new LuanyuException("密钥太短：至少需要 " + MIN_PASSPHRASE_CHARS
                        + " 位数字或字母（当前 " + keys[0].length() + " 位）");
            }
            headerLen = V1_HEADER_LEN;
            salt = Arrays.copyOfRange(frame, 3, headerLen);
        } else if (ver == VERSION2) {
            if (frame.length < V2_HEADER_LEN + IV_LEN + TAG_LEN_BITS / 8) {
                throw new LuanyuException("不是有效的乱语文本（内容过短或已损坏）");
            }
            int n = frame[3] & 0xFF;
            if (n < 1 || n > MAX_KEYS) {
                throw new LuanyuException("不是有效的乱语文本（内容已损坏）");
            }
            if (keys.length != n) {
                throw new LuanyuException("这串乱语由 " + n + " 把密钥加密，你提供了 "
                        + keys.length + " 把 — 请按相同顺序输入全部密钥");
            }
            headerLen = V2_HEADER_LEN;
            salt = Arrays.copyOfRange(frame, 4, headerLen);
        } else {
            throw new LuanyuException("乱语版本不兼容（v" + ver + "），请双方升级应用");
        }

        byte[] header = Arrays.copyOfRange(frame, 0, headerLen);
        byte[] iv = Arrays.copyOfRange(frame, headerLen, headerLen + IV_LEN);
        byte[] ct = Arrays.copyOfRange(frame, headerLen + IV_LEN, frame.length);

        try {
            byte[] dk = ver == VERSION1
                    ? deriveKey(keys[0], salt)
                    : deriveKeyMulti(keys, salt);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dk, "AES"),
                    new GCMParameterSpec(TAG_LEN_BITS, iv));
            gcm.updateAAD(header);
            byte[] plain = gcm.doFinal(ct);
            Arrays.fill(dk, (byte) 0);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new LuanyuException("解密失败：密钥不正确，或乱语已被篡改/损坏");
        } catch (GeneralSecurityException e) {
            throw new LuanyuException("解密失败：密钥不正确，或乱语已被篡改/损坏", e);
        }
    }

    // ============================================================ 密钥校验

    /** 校验多密钥数组: 去空白行 -> 1..10 把, 每把 >= 4 位。 */
    static String[] validateMultiKeys(String[] rawKeys) throws LuanyuException {
        List<String> list = new ArrayList<>();
        if (rawKeys != null) {
            for (String k : rawKeys) {
                String t = k == null ? "" : k.trim();
                if (!t.isEmpty()) {
                    list.add(t);
                }
            }
        }
        if (list.isEmpty()) {
            throw new LuanyuException("请至少输入 1 把密钥");
        }
        if (list.size() > MAX_KEYS) {
            throw new LuanyuException("最多支持 " + MAX_KEYS + " 把密钥（当前 "
                    + list.size() + " 把）");
        }
        String[] keys = list.toArray(new String[0]);
        for (int i = 0; i < keys.length; i++) {
            if (keys[i].length() < MIN_ADV_PASSPHRASE_CHARS) {
                throw new LuanyuException("第 " + (i + 1) + " 把密钥太短：至少 "
                        + MIN_ADV_PASSPHRASE_CHARS + " 位（当前 " + keys[i].length() + " 位）");
            }
        }
        return keys;
    }

    // ============================================================ 密钥推导

    static byte[] deriveKey(String passphrase, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt,
                PBKDF2_ITERATIONS, KEY_LEN_BYTES * 8);
        try {
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /** 链式推导: K1=PBKDF2(k1,salt); Ki=PBKDF2(ki, K(i-1)||salt)。顺序不同 => 密钥不同。 */
    static byte[] deriveKeyMulti(String[] keys, byte[] salt) throws GeneralSecurityException {
        byte[] k = null;
        for (String key : keys) {
            byte[] s;
            if (k == null) {
                s = salt;
            } else {
                s = new byte[k.length + salt.length];
                System.arraycopy(k, 0, s, 0, k.length);
                System.arraycopy(salt, 0, s, k.length, salt.length);
            }
            byte[] next = deriveKey(key, s);
            if (k != null) {
                Arrays.fill(k, (byte) 0);
            }
            k = next;
        }
        return k;
    }

    static String normalize(String passphrase) {
        if (passphrase == null) {
            return "";
        }
        return passphrase.trim();
    }

    private static byte[] buildHeader(int version, int n, byte[] salt) {
        int len = version == VERSION1 ? V1_HEADER_LEN : V2_HEADER_LEN;
        byte[] h = new byte[len];
        h[0] = MAGIC0;
        h[1] = MAGIC1;
        h[2] = (byte) version;
        if (version == VERSION2) {
            h[3] = (byte) n;
            System.arraycopy(salt, 0, h, 4, SALT_LEN);
        } else {
            System.arraycopy(salt, 0, h, 3, SALT_LEN);
        }
        return h;
    }

    // ============================================================ 乱码编码
    // 3 字节 -> 4 符号; 尾部 1/2 字节按标准 base64 位拼接规则补 0, 解码时校验残留位。

    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length + 2) / 3 * 4);
        int i = 0;
        while (i + 3 <= data.length) {
            int n = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8) | (data[i + 2] & 0xFF);
            sb.append(ALPHABET.charAt((n >>> 18) & 63));
            sb.append(ALPHABET.charAt((n >>> 12) & 63));
            sb.append(ALPHABET.charAt((n >>> 6) & 63));
            sb.append(ALPHABET.charAt(n & 63));
            i += 3;
        }
        int rem = data.length - i;
        if (rem == 1) {
            int n = (data[i] & 0xFF) << 16;
            sb.append(ALPHABET.charAt((n >>> 18) & 63));
            sb.append(ALPHABET.charAt((n >>> 12) & 63));
        } else if (rem == 2) {
            int n = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8);
            sb.append(ALPHABET.charAt((n >>> 18) & 63));
            sb.append(ALPHABET.charAt((n >>> 12) & 63));
            sb.append(ALPHABET.charAt((n >>> 6) & 63));
        }
        return sb.toString();
    }

    public static byte[] decode(String text) throws LuanyuException {
        // 允许空白混入(聊天软件换行/空格), 只取字母表内字符
        int n = 0;
        char[] tmp = new char[text.length()];
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                continue;
            }
            if (c > 127 || DECODE_MAP[c] < 0) {
                throw new LuanyuException("不是有效的乱语文本（含无法识别的字符 '" + sanitize(c) + "'）");
            }
            tmp[n++] = c;
        }
        if (n == 0) {
            return new byte[0];
        }
        if (n % 4 == 1) {
            throw new LuanyuException("不是有效的乱语文本（长度不合法，可能被截断）");
        }
        int outLen = n / 4 * 3 + (n % 4 == 2 ? 1 : (n % 4 == 3 ? 2 : 0));
        byte[] out = new byte[outLen];
        int oi = 0;
        int acc = 0, bits = 0;
        for (int i = 0; i < n; i++) {
            acc = (acc << 6) | DECODE_MAP[tmp[i]];
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[oi++] = (byte) ((acc >>> bits) & 0xFF);
            }
        }
        // 校验残留位必须为 0 (捕获同余篡改)
        if (bits > 0 && (acc & ((1 << bits) - 1)) != 0) {
            throw new LuanyuException("不是有效的乱语文本（内容已损坏）");
        }
        if (oi != outLen) {
            throw new LuanyuException("不是有效的乱语文本（内容已损坏）");
        }
        return out;
    }

    private static String sanitize(char c) {
        return (c < 0x20 || c == 0x7F) ? String.format("\\u%04X", (int) c) : String.valueOf(c);
    }

    // ============================================================ 密钥空间

    /** 估算单把密钥空间大小(种组合)。按字符类别取保守基数。 */
    public static double estimateKeySpace(String passphrase) {
        String k = normalize(passphrase);
        if (k.isEmpty()) {
            return 0;
        }
        boolean d = false, lo = false, up = false, sym = false, nonAscii = false;
        for (int i = 0; i < k.length(); ) {
            int cp = k.codePointAt(i);
            i += Character.charCount(cp);
            if (cp >= '0' && cp <= '9') d = true;
            else if (cp >= 'a' && cp <= 'z') lo = true;
            else if (cp >= 'A' && cp <= 'Z') up = true;
            else if (cp >= 0x20 && cp <= 0x7E) sym = true;
            else nonAscii = true;
        }
        int base;
        if (nonAscii) {
            base = 1000; // 非ASCII(如中文)按每字 1000 保守估计
        } else if (sym) {
            base = 95; // 含空格/符号: 整个可打印 ASCII 集
        } else if (lo && up && d) {
            base = 62;
        } else if ((lo || up) && d) {
            base = 36;
        } else if (lo && up) {
            base = 52;
        } else if (d) {
            base = 10;
        } else {
            base = 26;
        }
        int chars = k.codePointCount(0, k.length());
        return Math.pow(base, chars);
    }

    /**
     * 多密钥组合空间的 log10(各把空间乘积)。
     * 用对数避免 double 溢出(10 把密钥组合轻松超过 1e308)。
     */
    public static double combinedLog10(String[] rawKeys) {
        double sum = 0;
        if (rawKeys != null) {
            for (String k : rawKeys) {
                double s = estimateKeySpace(k);
                if (s > 1) {
                    sum += Math.log10(s);
                }
            }
        }
        return sum;
    }

    /** 中文友好紧凑格式: 568亿 / 3.5万亿 / 1.2×10^16 */
    public static String formatKeySpace(double space) {
        if (space <= 0 || Double.isNaN(space)) {
            return "0";
        }
        if (Double.isInfinite(space)) {
            return "10^308 以上";
        }
        if (space < 1e8) {
            return trimNum(space / 1e4) + " 万";
        }
        if (space < 1e12) {
            return trimNum(space / 1e8) + " 亿";
        }
        if (space < 1e16) {
            return trimNum(space / 1e12) + " 万亿";
        }
        int exp = (int) Math.floor(Math.log10(space));
        double mant = space / Math.pow(10, exp);
        return String.format(Locale.US, "%.1f×10^%d", mant, exp);
    }

    /** 由 log10 空间格式化(支持超大组合数, 如 10 把密钥)。 */
    public static String formatLog10(double log10space) {
        if (log10space <= 0) {
            return "0";
        }
        if (log10space < 16) {
            return formatKeySpace(Math.pow(10, log10space));
        }
        int exp = (int) Math.floor(log10space);
        double mant = Math.pow(10, log10space - exp);
        return String.format(Locale.US, "%.1f×10^%d", mant, exp);
    }

    private static String trimNum(double v) {
        if (v >= 100) {
            return String.format(Locale.US, "%.0f", v);
        }
        if (v >= 10) {
            return String.format(Locale.US, "%.1f", v);
        }
        return String.format(Locale.US, "%.2f", v);
    }
}
