/*
 * Copyright (c) 2009, 2020, Oracle and/or its affiliates. All rights reserved.
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

import java.security.AccessController;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.util.*;

import static sun.security.util.SecurityConstants.PROVIDER_VER;

/**
 * Provider class for the Edwards-curve Digital Signature Algorithm provider.
 * Supports EdDSA keypair and parameter generation and EdDSA signing.
 */
public class OpenEdDSA extends Provider {

    private static final long serialVersionUID = -2279741672933606418L;

    private static class ProviderService extends Provider.Service {

        ProviderService(Provider p, String type, String algo, String cn) {
            super(p, type, algo, cn, null, null);
        }

        ProviderService(Provider p, String type, String algo, String cn,
                        String[] aliases, HashMap<String, String> attrs) {
            super(p, type, algo, cn,
                    (aliases == null? null : Arrays.asList(aliases)), attrs);
        }

        @Override
        public Object newInstance(Object ctrParamObj)
                throws NoSuchAlgorithmException {
            String type = getType();
            if (ctrParamObj != null) {
                throw new InvalidParameterException
                        ("constructorParameter not used with " + type + " engines");
            }

            String algo = getAlgorithm();
            try {
                if (type.equals("Signature")) {
                    if (algo.equalsIgnoreCase("EdDSA")) {
                        return new EdDSASignature();
                    } else if (algo.equalsIgnoreCase("Ed25519")) {
                        return new EdDSASignature.Ed25519();
                    } else if (algo.equalsIgnoreCase("Ed448")) {
                        return new EdDSASignature.Ed448();
                    }
                } else  if (type.equals("KeyFactory")) {
                    if (algo.equalsIgnoreCase("EdDSA")) {
                        return new EdDSAKeyFactory();
                    } else if (algo.equalsIgnoreCase("Ed25519")) {
                        return new EdDSAKeyFactory.Ed25519();
                    } else if (algo.equalsIgnoreCase("Ed448")) {
                        return new EdDSAKeyFactory.Ed448();
                    }
                } else  if (type.equals("KeyPairGenerator")) {
                    if (algo.equalsIgnoreCase("EdDSA")) {
                        return new EdDSAKeyPairGenerator();
                    } else if (algo.equalsIgnoreCase("Ed25519")) {
                        return new EdDSAKeyPairGenerator.Ed25519();
                    } else if (algo.equalsIgnoreCase("Ed448")) {
                        return new EdDSAKeyPairGenerator.Ed448();
                    }
                }
            } catch (Exception ex) {
                throw new NoSuchAlgorithmException("Error constructing " +
                        type + " for " + algo + " using OpenEdDSA", ex);
            }
            throw new ProviderException("No impl for " + algo +
                    " " + type);
        }
    }

    public OpenEdDSA() {
        super("OpenEdDSA", PROVIDER_VER, "Open EdDSA algorithm provider");
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                putEdDSAEntries();
                return null;
            }
        });
    }

    private void putEdDSAEntries() {

        HashMap<String, String> ATTRS = new HashMap<>(1);
        ATTRS.put("ImplementedIn", "Software");

        /* EdDSA does not require native implementation */
        putService(new ProviderService(this, "KeyFactory",
                "EdDSA", "org.openeddsa.sun.security.ec.ed.EdDSAKeyFactory", null, ATTRS));
        putService(new ProviderService(this, "KeyFactory",
                "Ed25519", "org.openeddsa.sun.security.ec.ed.EdDSAKeyFactory.Ed25519",
                new String[]{"1.3.101.112", "OID.1.3.101.112"}, ATTRS));
        putService(new ProviderService(this, "KeyFactory",
                "Ed448", "org.openeddsa.sun.security.ec.ed.EdDSAKeyFactory.Ed448",
                new String[]{"1.3.101.113", "OID.1.3.101.113"}, ATTRS));

        putService(new ProviderService(this, "KeyPairGenerator",
                "EdDSA", "org.openeddsa.sun.security.ec.ed.EdDSAKeyPairGenerator", null, ATTRS));
        putService(new ProviderService(this, "KeyPairGenerator",
                "Ed25519", "org.openeddsa.sun.security.ec.ed.EdDSAKeyPairGenerator.Ed25519",
                new String[]{"1.3.101.112", "OID.1.3.101.112"}, ATTRS));
        putService(new ProviderService(this, "KeyPairGenerator",
                "Ed448", "org.openeddsa.sun.security.ec.ed.EdDSAKeyPairGenerator.Ed448",
                new String[]{"1.3.101.113", "OID.1.3.101.113"}, ATTRS));

        putService(new ProviderService(this, "Signature",
                "EdDSA", "org.openeddsa.sun.security.ec.ed.EdDSASignature", null, ATTRS));
        putService(new ProviderService(this, "Signature",
                "Ed25519", "org.openeddsa.sun.security.ec.ed.EdDSASignature.Ed25519",
                new String[]{"1.3.101.112", "OID.1.3.101.112"}, ATTRS));
        putService(new ProviderService(this, "Signature",
                "Ed448", "org.openeddsa.sun.security.ec.ed.EdDSASignature.Ed448",
                new String[]{"1.3.101.113", "OID.1.3.101.113"}, ATTRS));

    }
}
