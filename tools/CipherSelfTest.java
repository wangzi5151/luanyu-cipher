import com.wangzi5151.luanyucipher.crypto.CryptoCore;
import com.wangzi5151.luanyucipher.crypto.CryptoCore.LuanyuException;

import java.util.Arrays;
import java.util.Random;

/**
 * 乱语加密核心自测 — 不依赖 JUnit, 直接 javac/java 运行。
 * 运行见 tools/run-selftest.sh
 */
public class CipherSelfTest {

    static int passed = 0, failed = 0;

    static void check(boolean cond, String name) {
        if (cond) {
            passed++;
            System.out.println("  [PASS] " + name);
        } else {
            failed++;
            System.out.println("  [FAIL] " + name);
        }
    }

    interface Action {
        void run() throws LuanyuException;
    }

    static void expectReject(Action r, String name) {
        try {
            r.run();
            failed++;
            System.out.println("  [FAIL] " + name + " (未拒绝)");
        } catch (LuanyuException e) {
            passed++;
            System.out.println("  [PASS] " + name + " -> " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        final String KEY = "Xk7#9pQm";
        System.out.println("== 1. 往返一致性 ==");
        String[] samples = {
                "",
                "a",
                "Hello, World! 123",
                "中文测试：你好，世界！",
                "混合 mixed 文本 with emoji \uD83D\uDE80\uD83D\uDD10 and symbols @#$%",
                "多行\n文本\t制表符\r\n换行  结束",
                "《静夜思》床前明月光，疑是地上霜。举头望明月，低头思故乡。",
                repeat("很长的文本repeat-", 5000),
        };
        for (int i = 0; i < samples.length; i++) {
            String ct = CryptoCore.encrypt(KEY, samples[i]);
            String pt = CryptoCore.decrypt(KEY, ct);
            check(samples[i].equals(pt), "往返 #" + i + " (原文" + samples[i].length() + "字符, 乱语" + ct.length() + "字符)");
            check(ct.matches("[A-Za-z0-9@#]+"), "  输出纯乱码字符集 #" + i);
        }

        System.out.println("== 2. 同文不同密 (随机盐/IV) ==");
        String c1 = CryptoCore.encrypt(KEY, "同一段明文");
        String c2 = CryptoCore.encrypt(KEY, "同一段明文");
        check(!c1.equals(c2), "两次密文不同");
        String c3 = CryptoCore.encrypt(KEY, "同一段明文");
        check(!c1.equals(c3) && !c2.equals(c3), "三次密文互不相同");
        check(CryptoCore.decrypt(KEY, c1).equals(CryptoCore.decrypt(KEY, c3)), "不同密文均可解回同一原文");

        System.out.println("== 3. 错误密钥拒绝 ==");
        String ct = CryptoCore.encrypt(KEY, "机密内容 secret123");
        String ct2 = CryptoCore.encrypt("Xk7#9pQn", "另一把钥匙的密文不同");
        check(!ct.equals(ct2), "不同密钥产生不同密文");
        expectReject(() -> CryptoCore.decrypt("wrongpass", ct), "完全不同密钥");
        expectReject(() -> CryptoCore.decrypt("Xk7#9pQo", ct), "仅差一字的密钥");
        expectReject(() -> CryptoCore.decrypt("Xk7#9pQmm", ct), "更长的错误密钥");
        // 即使攻击者拿到正确密钥长度的错误猜测也必须失败
        expectReject(() -> CryptoCore.decrypt("AAAAAAAA", ct), "错误密钥A");

        System.out.println("== 4. 密文任意字节篡改拒绝 ==");
        byte[] frame = CryptoCore.decode(ct);
        for (int pos : new int[]{0, 1, 2, 3, 10, 18, 19, 30, 31, frame.length - 17, frame.length - 1}) {
            byte[] bad = frame.clone();
            bad[pos] ^= 0x01;
            final String tampered = CryptoCore.encode(bad);
            final int p = pos;
            expectReject(() -> CryptoCore.decrypt(KEY, tampered), "篡改帧字节@" + p);
        }
        // 截断
        String cut = ct.substring(0, ct.length() - 4);
        expectReject(() -> CryptoCore.decrypt(KEY, cut), "截断密文");
        // 追加
        expectReject(() -> CryptoCore.decrypt(KEY, ct + "A"), "追加字符");

        System.out.println("== 5. 格式校验 (非乱语文本) ==");
        expectReject(() -> CryptoCore.decrypt(KEY, "这不是乱语，这是普通中文一句话。"), "普通文本当密文");
        expectReject(() -> CryptoCore.decrypt(KEY, "!!!!"), "非法字符");
        expectReject(() -> CryptoCore.decrypt(KEY, ""), "空输入");
        expectReject(() -> CryptoCore.decrypt(KEY, "Y"), "单字符");

        System.out.println("== 6. 密钥长度下限 ==");
        expectReject(() -> CryptoCore.encrypt("abc", "x"), "3位密钥拒绝加密");
        expectReject(() -> CryptoCore.decrypt("abc1", ct), "4位密钥拒绝解密");
        expectReject(() -> CryptoCore.encrypt("abcde", "x"), "5位密钥拒绝加密");
        String six = CryptoCore.encrypt("abcdef", "6位可用");
        check(CryptoCore.decrypt("abcdef", six).equals("6位可用"), "6位密钥可用");
        expectReject(() -> CryptoCore.encrypt(null, "x"), "null密钥拒绝");

        System.out.println("== 7. 密钥空白规整 ==");
        String base = CryptoCore.encrypt("  Xk7#9pQm  ", "trim生效");
        check(CryptoCore.decrypt("Xk7#9pQm", base).equals("trim生效"), "首尾空白被忽略");
        String inner = CryptoCore.encrypt("ab cd ef", "内部空格");
        expectReject(() -> CryptoCore.decrypt("abcdef", inner), "内部空格是密钥的一部分");
        check(CryptoCore.decrypt("ab cd ef", inner).equals("内部空格"), "含内部空格密钥可用");

        System.out.println("== 8. 编解码层 ==");
        Random rnd = new Random(42);
        boolean codecOk = true, charOk = true;
        for (int len = 0; len <= 300 && codecOk && charOk; len++) {
            byte[] data = new byte[len];
            rnd.nextBytes(data);
            String enc = CryptoCore.encode(data);
            if (!enc.isEmpty() && !enc.matches("[A-Za-z0-9@#]+")) charOk = false;
            byte[] dec = CryptoCore.decode(enc);
            if (!Arrays.equals(data, dec)) {
                codecOk = false;
                System.out.println("    长度" + len + "不一致");
            }
        }
        check(codecOk, "随机字节 0..300 字节往返一致");
        check(charOk, "编码输出仅含字母表字符");
        // 解码容忍换行/空格(聊天软件可能加换行)
        String enc = CryptoCore.encode("hello world".getBytes("UTF-8"));
        String wrapped = enc.replaceAll("(.{10})", "$1\n");
        check(Arrays.equals(CryptoCore.decode(wrapped), "hello world".getBytes("UTF-8")), "解码容忍换行分隔");
        // 残留位校验: 构造尾部非法位
        try {
            byte[] bad = CryptoCore.decode("Y"); // n%4==1 非法
            check(false, "长度%4==1应拒绝");
        } catch (LuanyuException e) {
            check(true, "长度%4==1拒绝");
        }

        System.out.println("== 9. 密钥空间估算 ==");
        check(CryptoCore.estimateKeySpace("abcdef") == Math.pow(26, 6), "6位小写=26^6");
        check(CryptoCore.estimateKeySpace("123456") == Math.pow(10, 6), "6位数字=10^6");
        check(CryptoCore.estimateKeySpace("aB3xY9") == Math.pow(62, 6), "6位混合=62^6");
        check(CryptoCore.estimateKeySpace("abcdefg") == Math.pow(26, 7), "7位小写=26^7");
        check(CryptoCore.estimateKeySpace("秘密钥匙啊") == Math.pow(1000, 5), "5个汉字按1000/字");
        check(CryptoCore.estimateKeySpace("ab3@xy") == Math.pow(95, 6), "含符号=95^6");
        String f1 = CryptoCore.formatKeySpace(Math.pow(62, 6));
        String f2 = CryptoCore.formatKeySpace(Math.pow(62, 7));
        System.out.println("    6位混合 -> " + f1 + "; 7位混合 -> " + f2);
        check(f1.contains("亿") && !f1.contains("万亿"), "6位混合显示为'亿'级: " + f1);
        check(f2.contains("万亿"), "7位混合显示为'万亿'级: " + f2);
        System.out.println("    数字密钥 -> " + CryptoCore.formatKeySpace(Math.pow(10, 6)));
        System.out.println("    5位小写 -> " + CryptoCore.formatKeySpace(Math.pow(25, 6) * 26));

        System.out.println("== 10. 性能 (PBKDF2 600k) ==");
        long t0 = System.nanoTime();
        CryptoCore.encrypt(KEY, "benchmark");
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.println("    单次加密耗时 " + ms + " ms");
        t0 = System.nanoTime();
        CryptoCore.decrypt(KEY, CryptoCore.encrypt(KEY, "benchmark"));
        ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.println("    单次解密耗时 " + ms + " ms");
        check(ms < 30_000, "解密低于30秒 (实际" + ms + "ms)");

        System.out.println("== 11. 高级模式 (多密钥 Luanyu v2) ==");
        String[] k3 = {"Xk7#9pQm", "alpha2026", "381746"};
        String advCt = CryptoCore.encryptMulti(k3, "三把密钥保护的机密");
        check(CryptoCore.decryptMulti(k3, advCt).equals("三把密钥保护的机密"), "3 把密钥往返");
        // 顺序敏感
        String[] k3reordered = {"alpha2026", "Xk7#9pQm", "381746"};
        expectReject(() -> CryptoCore.decryptMulti(k3reordered, advCt), "顺序不同必须失败");
        // 缺一把
        expectReject(() -> CryptoCore.decryptMulti(new String[]{"Xk7#9pQm", "alpha2026"}, advCt), "缺一把密钥");
        // 多一把
        String[] k4 = {"Xk7#9pQm", "alpha2026", "381746", "extra99"};
        expectReject(() -> CryptoCore.decryptMulti(k4, advCt), "多一把密钥");
        // 错一把
        String[] k3wrong = {"Xk7#9pQm", "alpha2027", "381746"};
        expectReject(() -> CryptoCore.decryptMulti(k3wrong, advCt), "其中一把错误");
        // 基础模式解密多密钥乱语 -> 明确报错
        expectReject(() -> CryptoCore.decrypt("Xk7#9pQm", advCt), "基础模式解密 v2 乱语");
        // 高级模式解密基础 v1 乱语(单把>=6位) -> 应成功(自动识别)
        String v1ct = CryptoCore.encrypt("Xk7#9pQm", "基础模式旧密文");
        check(CryptoCore.decryptMulti(new String[]{"Xk7#9pQm"}, v1ct).equals("基础模式旧密文"),
                "高级模式向后兼容解密 v1");
        // v2 单把密钥
        String adv1 = CryptoCore.encryptMulti(new String[]{"abcdef"}, "单把高级");
        check(CryptoCore.decryptMulti(new String[]{"abcdef"}, adv1).equals("单把高级"), "v2 单密钥往返");
        check(CryptoCore.decrypt("abcdef", adv1).equals("单把高级"), "v2 单密钥可被基础模式解密");
        // 密钥数量边界
        String[] k10 = new String[10];
        for (int i = 0; i < 10; i++) k10[i] = "key" + (i * 17 + 31);
        String adv10 = CryptoCore.encryptMulti(k10, "十把密钥的极致保护");
        check(CryptoCore.decryptMulti(k10, adv10).equals("十把密钥的极致保护"), "10 把密钥往返");
        String[] k11 = new String[11];
        System.arraycopy(k10, 0, k11, 0, 10);
        k11[10] = "extra1";
        expectReject(() -> CryptoCore.encryptMulti(k11, "x"), "11 把密钥拒绝");
        expectReject(() -> CryptoCore.encryptMulti(new String[]{}, "x"), "0 把密钥拒绝");
        expectReject(() -> CryptoCore.encryptMulti(new String[]{"abc"}, "x"), "单把 3 位拒绝");
        // 每把 4 位可用(高级模式规则)
        String advMin = CryptoCore.encryptMulti(new String[]{"a1b2", "c3d4"}, "短但组合强");
        check(CryptoCore.decryptMulti(new String[]{"a1b2", "c3d4"}, advMin).equals("短但组合强"),
                "每把 4 位可用");
        // 空行忽略
        String[] kWithBlanks = {"Xk7#9pQm", "", "  ", "alpha2026", "381746"};
        check(CryptoCore.decryptMulti(kWithBlanks, advCt).equals("三把密钥保护的机密"), "空行被忽略");
        // v2 帧头(含 n)被篡改 -> 拒绝
        byte[] advFrame = CryptoCore.decode(advCt);
        byte[] tamperedN = advFrame.clone();
        tamperedN[3] ^= 0x01;
        final String advTampered = CryptoCore.encode(tamperedN);
        expectReject(() -> CryptoCore.decryptMulti(k3, advTampered), "篡改密钥数 n 字节");
        // 同文不同密(v2)
        String advCt2 = CryptoCore.encryptMulti(k3, "三把密钥保护的机密");
        check(!advCt.equals(advCt2), "v2 两次密文不同");
        // 组合密钥空间
        double log10 = CryptoCore.combinedLog10(k3);
        String fmt = CryptoCore.formatLog10(log10);
        System.out.println("    3 把密钥(" + String.join("+", k3) + ") 组合空间 -> " + fmt
                + " (log10=" + String.format("%.1f", log10) + ")");
        check(log10 > 12, "3 把混合密钥组合空间 > 10^12");
        check(CryptoCore.formatLog10(160.5).contains("10^"), "超大数科学计数: " + CryptoCore.formatLog10(160.5));
        // v1 旧密文仍可解(回归)
        check(CryptoCore.decrypt(KEY, CryptoCore.encrypt(KEY, "v1回归")).equals("v1回归"), "v1 回归");

        System.out.println();
        System.out.println("========================================");
        System.out.println("结果: " + passed + " 通过, " + failed + " 失败");
        if (failed > 0) {
            System.exit(1);
        }
        System.out.println("全部通过 ✓");
    }

    static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
