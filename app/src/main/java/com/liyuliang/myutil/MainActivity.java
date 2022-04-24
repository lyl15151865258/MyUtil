package com.liyuliang.myutil;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        EthernetUtil.setEthernetStaticIp(this,"192.168.10.236","255.255.255.0","192.168.10.1","192.168.10.1");

//        EthernetUtil.setDynamicIp(this);

//        ShellUtils.execCmd("reboot -p",true);
    }
}