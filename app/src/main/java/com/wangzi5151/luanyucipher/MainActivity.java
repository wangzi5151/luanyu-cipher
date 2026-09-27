package com.wangzi5151.luanyucipher;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.wangzi5151.luanyucipher.crypto.CryptoCore;

import java.util.Locale;

public class MainActivity extends Activity {

    private boolean encryptMode = true;
    private boolean busy = false;
    private boolean keyVisible = false;

    private EditText editKey;
    private EditText editInput;
    private TextView lblInput;
    private TextView lblOutput;
    private TextView txtOutput;
    private TextView txtKeySpace;
    private TextView txtStatus;
    private Button btnModeEnc;
    private Button btnModeDec;
    private Button btnRun;
    private Button btnPaste;
    private Button btnSwap;
    private Button btnClear;
    private Button btnCopy;
    private Button btnShare;
    private Button btnAbout;
    private Button btnToggleKey;
    private ProgressBar progress;

    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editKey = findViewById(R.id.editKey);
        editInput = findViewById(R.id.editInput);
        lblInput = findViewById(R.id.lblInput);
        lblOutput = findViewById(R.id.lblOutput);
        txtOutput = findViewById(R.id.txtOutput);
        txtKeySpace = findViewById(R.id.txtKeySpace);
        txtStatus = findViewById(R.id.txtStatus);
        btnModeEnc = findViewById(R.id.btnModeEnc);
        btnModeDec = findViewById(R.id.btnModeDec);
        btnRun = findViewById(R.id.btnRun);
        btnPaste = findViewById(R.id.btnPaste);
        btnSwap = findViewById(R.id.btnSwap);
        btnClear = findViewById(R.id.btnClear);
        btnCopy = findViewById(R.id.btnCopy);
        btnShare = findViewById(R.id.btnShare);
        btnAbout = findViewById(R.id.btnAbout);
        btnToggleKey = findViewById(R.id.btnToggleKey);
        progress = findViewById(R.id.progress);

        btnModeEnc.setOnClickListener(v -> setMode(true));
        btnModeDec.setOnClickListener(v -> setMode(false));
        btnRun.setOnClickListener(v -> runCrypto());
        btnToggleKey.setOnClickListener(v -> toggleKeyVisibility());
        btnPaste.setOnClickListener(v -> pasteFromClipboard());
        btnSwap.setOnClickListener(v -> swapContents());
        btnClear.setOnClickListener(v -> clearAll());
        btnCopy.setOnClickListener(v -> copyOutput());
        btnShare.setOnClickListener(v -> shareOutput());
        btnAbout.setOnClickListener(v -> showAbout());

        editKey.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
                updateKeySpace();
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });

        applyMode();
        updateKeySpace();
    }

    // ------------------------------------------------------------ 模式

    private void setMode(boolean encrypt) {
        if (busy || encryptMode == encrypt) {
            return;
        }
        encryptMode = encrypt;
        applyMode();
    }

    private void applyMode() {
        btnModeEnc.setSelected(encryptMode);
        btnModeDec.setSelected(!encryptMode);
        btnRun.setText(encryptMode ? R.string.mode_encrypt : R.string.mode_decrypt);
        lblInput.setText(encryptMode ? R.string.label_input_encrypt : R.string.label_input_decrypt);
        editInput.setHint(encryptMode ? R.string.hint_input_encrypt : R.string.hint_input_decrypt);
        lblOutput.setText(encryptMode ? R.string.label_output_encrypt : R.string.label_output_decrypt);
    }

    // ------------------------------------------------------------ 密钥空间

    private void updateKeySpace() {
        String k = editKey.getText().toString().trim();
        int min = CryptoCore.MIN_PASSPHRASE_CHARS;
        if (k.isEmpty()) {
            txtKeySpace.setText(R.string.keyspace_idle);
            txtKeySpace.setTextColor(getColor(R.color.textDim));
            return;
        }
        if (k.length() < min) {
            txtKeySpace.setText(String.format(Locale.CHINA,
                    "密钥仅 %d 位，太短 — 至少需要 %d 位", k.length(), min));
            txtKeySpace.setTextColor(getColor(R.color.error));
            return;
        }
        double space = CryptoCore.estimateKeySpace(k);
        String fmt = CryptoCore.formatKeySpace(space);
        if (space >= 1e12) {
            txtKeySpace.setText(String.format(Locale.CHINA,
                    "密钥空间 ≈ %s 种组合 ✓ 足够强", fmt));
            txtKeySpace.setTextColor(getColor(R.color.accent));
        } else {
            txtKeySpace.setText(String.format(Locale.CHINA,
                    "密钥空间 ≈ %s 种组合 — 建议加长到 7 位（≥3.5 万亿）", fmt));
            txtKeySpace.setTextColor(getColor(R.color.warn));
        }
    }

    // ------------------------------------------------------------ 执行

    private void runCrypto() {
        if (busy) {
            return;
        }
        final String key = editKey.getText().toString();
        final String input = editInput.getText().toString();
        final boolean encrypt = encryptMode;

        if (key.trim().length() < CryptoCore.MIN_PASSPHRASE_CHARS) {
            Toast.makeText(this, R.string.key_too_short, Toast.LENGTH_SHORT).show();
            editKey.requestFocus();
            return;
        }
        if (input.isEmpty()) {
            Toast.makeText(this, R.string.input_empty, Toast.LENGTH_SHORT).show();
            editInput.requestFocus();
            return;
        }

        setBusy(true);
        setStatus(getString(R.string.deriving), R.color.textDim);

        new Thread(() -> {
            long t0 = System.nanoTime();
            try {
                String out = encrypt
                        ? CryptoCore.encrypt(key, input)
                        : CryptoCore.decrypt(key, input);
                long ms = (System.nanoTime() - t0) / 1_000_000;
                final String msg = encrypt
                        ? String.format(Locale.CHINA,
                                "加密完成 · 原文 %d 字 → 乱语 %d 字符 · 耗时 %.1f 秒",
                                input.length(), out.length(), ms / 1000.0)
                        : String.format(Locale.CHINA,
                                "解密完成 · 乱语 %d 字符 → 原文 %d 字 · 耗时 %.1f 秒",
                                input.length(), out.length(), ms / 1000.0);
                post(() -> {
                    txtOutput.setText(out);
                    setStatus(msg, R.color.accent);
                });
            } catch (CryptoCore.LuanyuException e) {
                post(() -> {
                    setStatus("失败：" + e.getMessage(), R.color.error);
                    Toast.makeText(MainActivity.this, e.getMessage(),
                            Toast.LENGTH_LONG).show();
                });
            } catch (Throwable t) {
                final String m = "发生错误：" + t.getMessage();
                post(() -> {
                    setStatus(m, R.color.error);
                    Toast.makeText(MainActivity.this, m, Toast.LENGTH_LONG).show();
                });
            } finally {
                post(() -> setBusy(false));
            }
        }, "luanyu-crypto").start();
    }

    private void setBusy(boolean b) {
        busy = b;
        progress.setVisibility(b ? View.VISIBLE : View.GONE);
        btnRun.setEnabled(!b);
        btnModeEnc.setEnabled(!b);
        btnModeDec.setEnabled(!b);
        btnRun.setText(b ? R.string.deriving_short
                : (encryptMode ? R.string.mode_encrypt : R.string.mode_decrypt));
    }

    private void post(Runnable r) {
        main.post(() -> {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            r.run();
        });
    }

    private void setStatus(String msg, int colorRes) {
        txtStatus.setText(msg);
        txtStatus.setTextColor(getColor(colorRes));
    }

    // ------------------------------------------------------------ 剪贴板/交换

    private void pasteFromClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm == null || !cm.hasPrimaryClip()) {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        ClipData clip = cm.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        CharSequence text = clip.getItemAt(0).coerceToText(this);
        if (text == null || text.length() == 0) {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        editInput.setText(text);
        editInput.setSelection(editInput.getText().length());
    }

    private void copyOutput() {
        String out = txtOutput.getText().toString();
        if (out.isEmpty()) {
            Toast.makeText(this, R.string.nothing_to_share, Toast.LENGTH_SHORT).show();
            return;
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText(
                    encryptMode ? "乱语" : "原文", out));
            Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
        }
    }

    private void swapContents() {
        if (busy) {
            return;
        }
        String a = editInput.getText().toString();
        String b = txtOutput.getText().toString();
        if (a.isEmpty() && b.isEmpty()) {
            Toast.makeText(this, R.string.input_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        editInput.setText(b);
        editInput.setSelection(editInput.getText().length());
        txtOutput.setText(a);
        encryptMode = !encryptMode;
        applyMode();
        setStatus(encryptMode ? "已交换并切换到加密模式" : "已交换并切换到解密模式",
                R.color.textDim);
    }

    private void clearAll() {
        if (busy) {
            return;
        }
        editInput.setText("");
        txtOutput.setText("");
        setStatus("", R.color.textDim);
    }

    private void shareOutput() {
        String out = txtOutput.getText().toString();
        if (out.isEmpty()) {
            Toast.makeText(this, R.string.nothing_to_share, Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT, out);
        startActivity(Intent.createChooser(i, getString(R.string.btn_share)));
    }

    // ------------------------------------------------------------ 密钥可见性

    private void toggleKeyVisibility() {
        int sel = editKey.getSelectionStart();
        keyVisible = !keyVisible;
        editKey.setInputType(keyVisible
                ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        int len = editKey.getText().length();
        editKey.setSelection(Math.max(0, Math.min(sel < 0 ? len : sel, len)));
        btnToggleKey.setText(keyVisible ? R.string.key_hide : R.string.key_show);
    }

    // ------------------------------------------------------------ 关于

    private void showAbout() {
        String version;
        try {
            version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            version = "?";
        }
        String msg = "乱语 LuanyuCipher v" + version + "\n"
                + "密钥 + 原文 → 谁也看不懂的乱语\n\n"

                + "【加密方案 Luanyu v1】\n"
                + "· 密钥推导 PBKDF2-HMAC-SHA256，600,000 次迭代 + 16 字节随机盐\n"
                + "· 对称加密 AES-256-GCM（认证加密），12 字节随机 IV，128 位认证标签\n"
                + "· 帧头作为附加认证数据（AAD）：密文被改动任何一个字节都会解密失败\n"
                + "· 输出为 64 符号乱序字母表编码的纯 ASCII 乱文，可安全过微信/短信\n\n"

                + "【强度】\n"
                + "· 同一段原文，每次加密输出都不同（随机盐 + 随机 IV）\n"
                + "· 不内嵌密钥校验位：不知道原文任何片段时，攻击者无法验证密钥猜测\n"
                + "· 6 位混合密钥 ≈ 568 亿种组合；7 位 ≈ 3.5 万亿种\n"
                + "· 本应用不申请任何权限（无 INTERNET），物理上无法外传数据\n\n"

                + "【使用提示】\n"
                + "· 密钥请另走渠道告诉对方，不要和乱语一起发送\n"
                + "· 密钥不被保存：关闭应用即遗忘，请自行妥善保管\n"
                + "· 乱语若被篡改，解密会明确报错，绝不会输出错误的『原文』";
        new AlertDialog.Builder(this)
                .setTitle("关于乱语")
                .setMessage(msg)
                .setPositiveButton("知道了", null)
                .show();
    }
}
