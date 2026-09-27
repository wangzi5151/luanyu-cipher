package com.wangzi5151.luanyucipher.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 乱语 Luanyu v1 — 认证加密方案。
 *
 * 结构:
 *   密钥: PBKDF2-HMAC-SHA256(passphrase, salt, 600000) -> 256bit AES 密钥
 *   加密: AES-256-GCM(iv=random 12B, aad = 帧头) -> 密文+128bit 认证标签
 *   帧:   'L' 'Y' ver(0x01) salt(16) iv(12) ciphertext||tag
 *   编码: 64 符号乱序字母表, 3字节->4字符, 无填充
 *
 * 无密钥校验位: 不嵌入任何可快速验证密钥的字段,
 * 攻击者在不知道原文任何片段时无法验证密钥猜测。
 */
public final class CryptoCore {

    public static final int VERSION = 0x01;
    public static final int PBKDF2_ITERATIONS = 600_000;
    public static final int MIN_PASSPHRASE_CHARS = 6;
    public static final int SALT_LEN = 16;
    public static final int IV_LEN = 12;
    public static final int TAG_LEN_BITS = 128;
    public static final int KEY_LEN_BYTES = 32;
    public static final int HEADER_LEN = 3 + SALT_LEN; // 'L' 'Y' ver salt

    private static final byte MAGIC0 = 'L';
    private static final byte MAGIC1 = 'Y';
    private static final int FRAME_PREFIX = HEADER_LEN + IV_LEN;

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

    // ------------------------------------------------------------ 加密

    public static String encrypt(String passphrase, String plaintext) throws LuanyuException {
        String key = normalize(passphrase);
        checkMinLength(key);
        if (plaintext == null) {
            throw new LuanyuException("原文不能为空");
        }
        try {
            SecureRandom rng = new SecureRandom();
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(salt);
            rng.nextBytes(iv);

            byte[] dk = deriveKey(key, salt);
            byte[] header = buildHeader(salt);

            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dk, "AES"),
                    new GCMParameterSpec(TAG_LEN_BITS, iv));
            gcm.updateAAD(header);
            byte[] ct = gcm.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Arrays.fill(dk, (byte) 0);

            byte[] frame = new byte[FRAME_PREFIX + ct.length];
            System.arraycopy(header, 0, frame, 0, HEADER_LEN);
            System.arraycopy(iv, 0, frame, HEADER_LEN, IV_LEN);
            System.arraycopy(ct, 0, frame, FRAME_PREFIX, ct.length);
            return encode(frame);
        } catch (GeneralSecurityException e) {
            throw new LuanyuException("加密失败: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------ 解密

    public static String decrypt(String passphrase, String garbledText) throws LuanyuException {
        String key = normalize(passphrase);
        checkMinLength(key);
        if (garbledText == null || garbledText.isEmpty()) {
            throw new LuanyuException("请先粘贴收到的乱语");
        }
        byte[] frame = decode(garbledText);
        if (frame.length < FRAME_PREFIX + TAG_LEN_BITS / 8) {
            throw new LuanyuException("不是有效的乱语文本（内容过短或已损坏）");
        }
        if (frame[0] != MAGIC0 || frame[1] != MAGIC1) {
            throw new LuanyuException("不是有效的乱语文本（请确认完整粘贴，未被截断或改写）");
        }
        if ((frame[2] & 0xFF) != VERSION) {
            throw new LuanyuException("乱语版本不兼容（v" + (frame[2] & 0xFF) + "），请双方升级应用");
        }

        byte[] header = Arrays.copyOfRange(frame, 0, HEADER_LEN);
        byte[] iv = Arrays.copyOfRange(frame, HEADER_LEN, FRAME_PREFIX);
        byte[] ct = Arrays.copyOfRange(frame, FRAME_PREFIX, frame.length);

        try {
            byte[] dk = deriveKey(key, Arrays.copyOfRange(header, 3, HEADER_LEN));
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

    // ------------------------------------------------------------ 密钥推导

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

    static String normalize(String passphrase) {
        if (passphrase == null) {
            return "";
        }
        return passphrase.trim();
    }

    static void checkMinLength(String key) throws LuanyuException {
        if (key.length() < MIN_PASSPHRASE_CHARS) {
            throw new LuanyuException("密钥太短：至少需要 " + MIN_PASSPHRASE_CHARS
                    + " 位数字或字母（当前 " + key.length() + " 位）");
        }
    }

    private static byte[] buildHeader(byte[] salt) {
        byte[] h = new byte[HEADER_LEN];
        h[0] = MAGIC0;
        h[1] = MAGIC1;
        h[2] = (byte) VERSION;
        System.arraycopy(salt, 0, h, 3, SALT_LEN);
        return h;
    }

    // ------------------------------------------------------------ 乱码编码
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

    // ------------------------------------------------------------ 密钥空间

    /** 估算密钥空间大小(种组合)。按字符类别取保守基数。 */
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

    /** 中文友好紧凑格式: 568亿 / 3.5万亿 / 1.2×10^16 */
    public static String formatKeySpace(double space) {
        if (space <= 0) {
            return "0";
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
        return String.format(java.util.Locale.US, "%.1f×10^%d", mant, exp);
    }

    private static String trimNum(double v) {
        if (v >= 100) {
            return String.format(java.util.Locale.US, "%.0f", v);
        }
        if (v >= 10) {
            return String.format(java.util.Locale.US, "%.1f", v);
        }
        return String.format(java.util.Locale.US, "%.2f", v);
    }
}
