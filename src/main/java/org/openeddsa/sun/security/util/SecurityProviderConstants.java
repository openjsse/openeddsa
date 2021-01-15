/*
 * Copyright (c) 2017, 2020, Oracle and/or its affiliates. All rights reserved.
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

package org.openeddsa.sun.security.util;

import java.util.regex.PatternSyntaxException;
import sun.security.action.GetPropertyAction;
import sun.security.util.Debug;

/**
 * Various constants such as version number, default key length, used by
 * the JDK security/crypto providers.
 */
public final class SecurityProviderConstants {
    private static final Debug debug =
        Debug.getInstance("jca", "ProviderConfig");

    // Cannot create one of these
    private SecurityProviderConstants () {
    }

    public static final int DEF_ED_KEY_SIZE;

    private static final String KEY_LENGTH_PROP =
        "jdk.security.defaultKeySize";
    static {
        String keyLengthStr = GetPropertyAction.privilegedGetProperty
            (KEY_LENGTH_PROP);
        int edKeySize = 255;

        if (keyLengthStr != null) {
            try {
                String[] pairs = keyLengthStr.split(",");
                for (String p : pairs) {
                    String[] algoAndValue = p.split(":");
                    if (algoAndValue.length != 2) {
                        // invalid pair, skip to next pair
                        if (debug != null) {
                            debug.println("Ignoring invalid pair in " +
                                KEY_LENGTH_PROP + " property: " + p);
                        }
                        continue;
                    }
                    String algoName = algoAndValue[0].trim().toUpperCase();
                    int value = -1;
                    try {
                        value = Integer.parseInt(algoAndValue[1].trim());
                    } catch (NumberFormatException nfe) {
                        // invalid value, skip to next pair
                        if (debug != null) {
                            debug.println("Ignoring invalid value in " +
                                KEY_LENGTH_PROP + " property: " + p);
                        }
                        continue;
                    }
                    if (algoName.equalsIgnoreCase("EdDSA")) {
                        edKeySize = value;
                    } else {
                        // other algorithms handled by sun.security.util.SecurityProviderConstants
                        continue;
                    }
                    if (debug != null) {
                        debug.println("Overriding default " + algoName +
                            " keysize with value from " +
                            KEY_LENGTH_PROP + " property: " + value);
                    }
                }
            } catch (PatternSyntaxException pse) {
                // if property syntax is not followed correctly
                if (debug != null) {
                    debug.println("Unexpected exception while parsing " +
                        KEY_LENGTH_PROP + " property: " + pse);
                }
            }
        }
        DEF_ED_KEY_SIZE = edKeySize;
    }
}
