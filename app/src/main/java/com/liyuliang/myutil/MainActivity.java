package com.liyuliang.myutil;

import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Log.d("MainActivity", "ip：" + EthernetUtil.getIpAddress());
        Log.d("MainActivity", "网关：" + EthernetUtil.getGateWay());
        Log.d("MainActivity", "DNS：" + EthernetUtil.getDns(this));
        Log.d("MainActivity", "子网掩码：" + EthernetUtil.getNetMask());
        EthernetUtil.setEthernetPppoe(this,"123456","123456");

//        EthernetUtil.setDynamicIp(this);

//        ShellUtils.execCmd("reboot -p",true);
    }
}