/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeddsa.sun.security.ec.ed;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import org.openeddsa.java.security.interfaces.EdECPrivateKey;
import java.util.Optional;
import org.openeddsa.java.security.spec.NamedParameterSpec;

import sun.security.pkcs.PKCS8Key;
import sun.security.x509.AlgorithmId;
import sun.security.util.*;

public final class EdDSAPrivateKeyImpl
        extends PKCS8Key implements EdECPrivateKey {

    private static final long serialVersionUID = 1L;

    private final NamedParameterSpec paramSpec;
    private byte[] h;

    EdDSAPrivateKeyImpl(EdDSAParameters params, byte[] h)
            throws InvalidKeyException {

        this.paramSpec = new NamedParameterSpec(params.getName());
        this.algid = new AlgorithmId(params.getOid());
        this.h = h.clone();

        encodeKey();

        checkLength(params);
    }

    EdDSAPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {

        decode(encoded);
        EdDSAParameters params = EdDSAParameters.get(
                InvalidKeyException::new, algid);
        paramSpec = new NamedParameterSpec(params.getName());

        decodeKey();

        checkLength(params);
    }

    private void decodeKey() throws InvalidKeyException {
        try {
            DerInputStream derStream = new DerInputStream(key);
            h = derStream.getOctetString();
        } catch (IOException ex) {
            throw new InvalidKeyException(ex);
        }
    }

    private void encodeKey() {
        DerOutputStream derKey = new DerOutputStream();
        try {
            derKey.putOctetString(h);
            this.key = derKey.toByteArray();
        } catch (IOException ex) {
            throw new ProviderException(ex);
        }
    }

    void checkLength(EdDSAParameters params) throws InvalidKeyException {

        if (params.getKeyLength() != this.h.length) {
            throw new InvalidKeyException("key length is " + this.h.length +
                    ", key length must be " + params.getKeyLength());
        }
    }

    public byte[] getKey() {
        return h.clone();
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    @Override
    public NamedParameterSpec getParams() {
        return paramSpec;
    }

    @Override
    public Optional<byte[]> getBytes() {
        return Optional.of(getKey());
    }
}