package com.vulnerable;

public class CommandInjection {
    public void pingHost(String userHost) {
        try {
            Runtime.getRuntime().exec("ping -c 4 " + userHost);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
