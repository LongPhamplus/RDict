package com.rdict.t2;
import java.io.*;
public class AntiHook {
    public static boolean scan() {
        try (BufferedReader r = new BufferedReader(new FileReader(Z.a("VAwPERyv8ufv4qrr5vj6", 123)))) {
            String l; String needle = Z.a("UUpQXloRTltNNiQw", 55);
            while ((l = r.readLine()) != null) if (l.contains(needle)) return true;
        } catch (IOException e) { }
        return false;
    }
}