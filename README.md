OpenEdDSA
----------------------------------------------

----------------------------------------------------------------------------
OpenEdDSA: A JCE provider that supports KeyPairGenerator, KeyFactory and Signature
for the EdDSA crypto algorithms on Java SE 8.

The OpenEdDSA project is created to add support for EdDSA crypto algorithms
to existing Java 8 applications without requiring code changes. 

The public API for OpenEdDSA is located in the org.openeddsa.java.security.spec
and org.openeddsa.java.security.interfaces packages and is similar to the
java.security.spec and java.security.interfaces package APIs introduced by JEP-339. 

----
### Installation

Installation of OpenEdDSA provider is done in two steps:
1. Add the OpenEdDSA provider jar to the $JAVA_HOME/jre/lib/ext directory
2. Create an OpenEdDSA provider entry in the $JAVA_HOME/jre/lib/security/java.security file

The entry to java.security will look something like the following:
>  security.provider.N=org.openeddsa.security.OpenEdDSA

Replace N with last entry in the list of providers

----
### Code origins and evolution

The project code is comprised primarily of a backport of the JEP-339
to Java 8. While small modification were needed in order to make the
code work on Java 8 JREs, the structure of the original code has been
kept mostly intact, with associated packages placed under the
org.openeddsa.* namespace to avoid collisions.

The code for this project is licensed under the OpenJDK GPLv2 + CPE
license, as described in the LICENSE file at the base of this repository
and in notices found in the various source files.
