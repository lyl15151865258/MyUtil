package com.liyuliang.myutil;

import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.d("MainActivity", "网络：" + EthernetUtil.getIpAssignment(this));


//        EthernetUtil.setDynamicIp(this);

//        ShellUtils.execCmd("reboot -p",true);
    }
}