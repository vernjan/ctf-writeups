//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hackyeaster.eggcryptor;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.io.InputStream;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {
    public MainActivity() {
    }

    protected void onCreate(Bundle var1) {
        super.onCreate(var1);
        this.setContentView(2131427356);
        Button var2 = (Button)this.findViewById(2131230756);
        final ImageView var3 = (ImageView)this.findViewById(2131230805);
        final EditText var4 = (EditText)this.findViewById(2131230838);
        final Pattern var5 = Pattern.compile(this.getResources().getString(2131689529));
        Object var6 = null;
        byte[] var11 = (byte[])var6;

        label39: {
            boolean var10001;
            InputStream var7;
            try {
                var7 = this.getResources().openRawResource(2131623936);
            } catch (Exception var10) {
                var10001 = false;
                break label39;
            }

            var11 = (byte[])var6;

            byte[] var12;
            try {
                var12 = new byte[var7.available()];
            } catch (Exception var9) {
                var10001 = false;
                break label39;
            }

            var11 = var12;

            try {
                var7.read(var12);
            } catch (Exception var8) {
                var10001 = false;
                break label39;
            }

            var11 = var12;
        }

        var2.setOnClickListener(new OnClickListener(new String(var11)) {
            {
                this.val$r = var4x;
            }

            public void onClick(View var1) {
                if (var5.matcher(var4.getText()).matches()) {
                    try {
                        byte[] var3x = Crypto.decrypt(var4.getText().toString(), this.val$r);
                        Bitmap var4x = BitmapFactory.decodeByteArray(var3x, 0, var3x.length);
                        var3.setImageBitmap(var4x);
                    } catch (Exception var2) {
                        var3.setImageBitmap((Bitmap)null);
                    }
                } else {
                    Toast.makeText(MainActivity.this.getApplicationContext(), MainActivity.this.getResources().getString(2131689523), 1).show();
                }

            }
        });
    }
}
