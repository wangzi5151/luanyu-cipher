package com.wangzi5151.luanyucipher.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;

import com.wangzi5151.luanyucipher.crypto.CryptoCore.LuanyuException;

public class CryptoCoreTest {

    private static final String KEY = "Xk7#9pQm";

    private interface Action {
        void run() throws Exception;
    }

    private static void expectReject(String name, Action action) {
        try {
            action.run();
            fail(name + " 未被拒绝");
        } catch (LuanyuException expected) {
            // 预期路径
        } catch (Exception e) {
            fail(name + " 抛出了意外的异常: " + e);
        }
    }

    @Test
    public void v2RoundTripWithSingleAndTenKeys() throws Exception {
        String one = CryptoCore.encryptMulti(new String[]{"abcdef"}, "v2 单把密钥");
        assertEquals("v2 单把密钥", CryptoCore.decryptMulti(new String[]{"abcdef"}, one));

        String[] ten = new String[10];
        for (int i = 0; i < ten.length; i++) {
            ten[i] = "key" + (i * 17 + 31);
        }
        String tenText = "十把密钥的边界往返";
        String tenCt = CryptoCore.encryptMulti(ten, tenText);
        assertEquals(tenText, CryptoCore.decryptMulti(ten, tenCt));
    }

    @Test
    public void v2RejectsWrongKeyAndWrongOrder() throws Exception {
        String[] keys = {"Xk7#9pQm", "alpha2026", "381746"};
        String text = "三把密钥保护的机密";
        String ct = CryptoCore.encryptMulti(keys, text);

        expectReject("错误密钥", () -> CryptoCore.decryptMulti(
                new String[]{"Xk7#9pQm", "alpha2027", "381746"}, ct));
        expectReject("顺序错误", () -> CryptoCore.decryptMulti(
                new String[]{"alpha2026", "Xk7#9pQm", "381746"}, ct));
        String one = CryptoCore.encryptMulti(new String[]{"abcdef"}, text);
        expectReject("单把错误密钥", () -> CryptoCore.decryptMulti(
                new String[]{"abcdeg"}, one));
    }

    @Test
    public void v2RejectsWrongKeyCount() throws Exception {
        String ct = CryptoCore.encryptMulti(new String[]{"Xk7#9pQm", "alpha2026"}, "双密钥");
        expectReject("少一把密钥", () -> CryptoCore.decryptMulti(
                new String[]{"Xk7#9pQm"}, ct));
        expectReject("多一把密钥", () -> CryptoCore.decryptMulti(
                new String[]{"Xk7#9pQm", "alpha2026", "381746"}, ct));
    }

    @Test
    public void v2RejectsTruncatedCiphertext() throws Exception {
        String[] keys = {"Xk7#9pQm", "alpha2026"};
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            sb.append("长文本边界测试 ");
        }
        String ct = CryptoCore.encryptMulti(keys, sb.toString());

        expectReject("截断 4 字符", () -> CryptoCore.decryptMulti(
                keys, ct.substring(0, ct.length() - 4)));
        expectReject("截断 3 字符(长度%4==1)", () -> CryptoCore.decryptMulti(
                keys, ct.substring(0, ct.length() - 3)));
        expectReject("截断 1 字符", () -> CryptoCore.decryptMulti(
                keys, ct.substring(0, ct.length() - 1)));
    }

    @Test
    public void v2RejectsInvalidKeyCountHeader() throws Exception {
        String[] keys = {"Xk7#9pQm", "alpha2026"};
        String ct = CryptoCore.encryptMulti(keys, "帧头边界");
        byte[] frame = CryptoCore.decode(ct);

        byte[] zero = frame.clone();
        zero[3] = 0;
        expectReject("密钥数 n=0", () -> CryptoCore.decryptMulti(keys, CryptoCore.encode(zero)));

        byte[] tooMany = frame.clone();
        tooMany[3] = 11;
        expectReject("密钥数 n=11", () -> CryptoCore.decryptMulti(keys, CryptoCore.encode(tooMany)));
    }

    @Test
    public void v2RejectsFrameShorterThanMinimum() throws Exception {
        String[] keys = {"Xk7#9pQm", "alpha2026"};
        byte[] frame = CryptoCore.decode(CryptoCore.encryptMulti(keys, "最小帧边界"));
        int minV2Frame = CryptoCore.V2_HEADER_LEN + CryptoCore.IV_LEN
                + CryptoCore.TAG_LEN_BITS / 8;

        String tooShort = CryptoCore.encode(Arrays.copyOf(frame, minV2Frame - 1));
        expectReject("v2 帧不足最小长度", () -> CryptoCore.decryptMulti(keys, tooShort));
    }

    @Test
    public void v2RejectsInvalidKeyLengthsAndCounts() throws Exception {
        expectReject("0 把密钥", () -> CryptoCore.encryptMulti(new String[0], "x"));
        expectReject("11 把密钥", () -> CryptoCore.encryptMulti(new String[]{
                "key01", "key02", "key03", "key04", "key05", "key06",
                "key07", "key08", "key09", "key10", "key11"}, "x"));
        expectReject("单把 3 位", () -> CryptoCore.encryptMulti(new String[]{"abc"}, "x"));
        expectReject("空密钥与空白行", () -> CryptoCore.encryptMulti(
                new String[]{null, "", "  ", "abc"}, "x"));

        String ct = CryptoCore.encryptMulti(new String[]{"a1b2", "c3d4"}, "每把 4 位可用");
        assertEquals("每把 4 位可用", CryptoCore.decryptMulti(new String[]{"a1b2", "c3d4"}, ct));
    }

    @Test
    public void decodeRejectsTruncatedOrMalformedTail() throws Exception {
        String ct = CryptoCore.encrypt(KEY, "编解码边界");
        expectReject("长度%4==1", () -> CryptoCore.decode(ct.substring(0, 5)));
        expectReject("单字符", () -> CryptoCore.decode("Y"));
    }
}
