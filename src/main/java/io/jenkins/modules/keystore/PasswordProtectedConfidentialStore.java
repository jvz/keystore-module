/*
 * The MIT License
 *
 * Copyright (c) 2020 Matt Sicker, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

package io.jenkins.modules.keystore;

import jenkins.model.Jenkins;
import jenkins.security.ConfidentialKey;
import jenkins.security.ConfidentialStore;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.kohsuke.MetaInfServices;

import javax.annotation.CheckForNull;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

@MetaInfServices
public class PasswordProtectedConfidentialStore extends ConfidentialStore {

    private static final String KEY = "AES";
    private static final String CIPHER = "AES/GCM/NoPadding";

    private final Path root;
    private final SecureRandom random;
    private final SecretKey masterKey;

    public PasswordProtectedConfidentialStore() {
        try {
            root = Jenkins.get().root.toPath().resolve("secrets");
            if (Files.notExists(root)) {
                Files.createDirectory(root,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            }
            random = SecureRandom.getInstanceStrong();
            masterKey = readKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No support for password-based encryption", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private SecretKey readKey() throws IOException {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("No console available to unlock Jenkins");
        }
        char[] password;
        byte[] salt;
        Path saltFile = root.resolve("master.salt");
        if (Files.exists(saltFile)) {
            salt = readSalt(saltFile);
            password = console.readPassword("Enter master key password to unlock Jenkins: ");
        } else {
            salt = generateSalt(saltFile);
            do {
                password = console.readPassword("Enter new master key password to encrypt secrets: ");
            } while (!Arrays.equals(password, console.readPassword("Re-enter password: ")));
        }
        return deriveKey(password, salt);
    }

    private byte[] generateSalt(Path saltFile) throws IOException {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);
        Files.write(saltFile, Collections.singleton(saltString), StandardOpenOption.CREATE_NEW);
        return salt;
    }

    private static byte[] readSalt(Path saltFile) throws IOException {
        byte[] salt;
        String saltString = Files.readAllLines(saltFile).get(0);
        salt = Base64.getDecoder().decode(saltString);
        return salt;
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withParallelism(2)
                .withMemoryAsKB(102400)
                .withIterations(2)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] hash = new byte[16];
        generator.generateBytes(password, hash);
        return new SecretKeySpec(hash, KEY);
    }

    @Override
    protected void store(ConfidentialKey key, byte[] payload) throws IOException {
        String keyId = key.getId();
        Path keyFile = root.resolve(keyId);
        byte[] iv = randomBytes(16);
        GCMParameterSpec params = new GCMParameterSpec(128, iv);
        try (OutputStream os = Files.newOutputStream(keyFile)) {
            os.write(iv);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, params, random);
            cipher.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
            try (CipherOutputStream out = new CipherOutputStream(os, cipher)) {
                out.write(payload);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    @CheckForNull
    @Override
    protected byte[] load(ConfidentialKey key) throws IOException {
        String keyId = key.getId();
        Path keyFile = root.resolve(keyId);
        if (Files.notExists(keyFile)) {
            return null;
        }
        byte[] iv = new byte[16];
        try (InputStream is = Files.newInputStream(keyFile)) {
            if (is.read(iv) != 16) {
                throw new IOException("Cannot read IV of " + keyId);
            }
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, params);
            cipher.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
            try (CipherInputStream in = new CipherInputStream(is, cipher)) {
                return IOUtils.toByteArray(in);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] randomBytes(int size) {
        if (size > 100000) {
            throw new IllegalArgumentException("Too much random: " + size);
        }
        byte[] buf = new byte[size];
        random.nextBytes(buf);
        return buf;
    }
}
