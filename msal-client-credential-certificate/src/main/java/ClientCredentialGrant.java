// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;

import org.neo4j.driver.*;

import static org.neo4j.driver.Values.parameters;

class ClientCredentialGrant {

    private static String authority;
    private static String clientId;
    private static String scope;
    private static String keyPath;
    private static String certPath;
    private static Config config;

    public static void main(String args[]) throws Exception {

        setUpSampleData();

       // String mySSOToken = "";



        try {
            // IAuthenticationResult result = getAccessTokenByClientCredentialGrant();
           simpleSampleUsingAccessToken("");
           // impersonationSampleUsingUsernamePassword("");

            System.out.println("Did something");
            System.out.println("Press any key to exit ...");
            System.in.read();

        } catch(Exception ex){
            System.out.println("Oops! We have an exception of type - " + ex.getClass());
            System.out.println("Exception message - " + ex.getMessage());
            throw ex;
        }
    }


    private static IAuthenticationResult getAccessTokenByClientCredentialGrant() throws Exception {

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(keyPath)));
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(spec);

        InputStream certStream = new ByteArrayInputStream(Files.readAllBytes(Paths.get(certPath)));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);

        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                clientId,
                ClientCredentialFactory.createFromCertificate(key, cert))
                .authority(authority)
                .build();

        // With client credentials flows the scope is ALWAYS of the shape "resource/.default", as the
        // application permissions need to be set statically (in the portal), and then granted by a tenant administrator

        ClientCredentialParameters clientCredentialParam = ClientCredentialParameters.builder(
                Collections.singleton(scope))
                .build();

        CompletableFuture<IAuthenticationResult> future = app.acquireToken(clientCredentialParam);
        return future.get();
    }

    private static void simpleSampleUsingAccessToken(String accessToken)  {
        String myToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imwzc1EtNTBjQ0g0eEJWWkxIVEd3blNSNzY4MCJ9.eyJhdWQiOiIyN2EyMTMxYS01MmRjLTRhNTctYmI0My1kN2Y3NTNjNDRjN2EiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNTU1ZWU3ZGQtNTUyNi00YjNkLWEzNWYtYjg1MjYzYjExNGU3L3YyLjAiLCJpYXQiOjE2MzYwMzQ4NDYsIm5iZiI6MTYzNjAzNDg0NiwiZXhwIjoxNjM2MDM4NzQ2LCJhaW8iOiJBV1FBbS84VEFBQUFIUW5jbVkwVnZoZ3lNSWhmbGVIWDNMMlZjREJKa3EvaFJKSE1vMVpzbmozMHJrL2FOVU05S3NDSThxYVFqMmRjY2VJa2NQNlVRVmp2SDZDMTBsbkpPc2NPR2lGZW11NlNQQ3lNa21kRzhkNGNwUGRaaHBFNHdFaUJzdUFPY2pIQyIsImVtYWlsIjoicmljaGFyZC5tYWNhc2tpbGxAb3V0bG9vay5jb20iLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85MTg4MDQwZC02YzY3LTRjNWItYjExMi0zNmEzMDRiNjZkYWQvIiwibmFtZSI6IlJpY2ggTWFjYXNraWxsIiwib2lkIjoiYTJmZWM0YjUtYWM5NC00NmFlLTgwNzYtZmRmMTQzM2RmY2NlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicmljaGFyZC5tYWNhc2tpbGxAb3V0bG9vay5jb20iLCJyaCI6IjAuQVFzQTNlZGVWU1pWUFV1alg3aFNZN0VVNXhvVG9pZmNVbGRLdTBQWDkxUEVUSG9MQUgwLiIsInJvbGVzIjpbImFkbWluIl0sInN1YiI6InljZjhuNGJrRjd6eWhmNHlYdHJuNlFrVjBLajNWZWJXUjJURzA2X3M2SDQiLCJ0aWQiOiI1NTVlZTdkZC01NTI2LTRiM2QtYTM1Zi1iODUyNjNiMTE0ZTciLCJ1dGkiOiJWRlFWekVaRnowT1lZQXFPNW9vd0FBIiwidmVyIjoiMi4wIn0.F_MbE4AthT1G6PFEZ24Wu3UjBt7ltnnITVd0HCbdMdcEhPR4PYfJkHK5FOi-Nhd19X_X0GQ3QSQqWfSn6-uOeJa36DeEeKLRO-ZZWXng4JDVVgxPeniL1XRd09lYd_3WJJIthGR9HCB4UsqDD2K-KZyw2Q7tDUktazSgQrMSKSNauxx9X_hm2ryLItTXqtVQ9O9ZtEghVLbhN2vkgWgSZqzwpRlz_TuDbQQzgBJVguS8xEH2ldy_PB-3ZFs_wS0fBQlP2pBwiPDe0kv6hIG6svhPMZMHQ9L__zY88WotI9kVYqR1qAUCgYSqQS5T9nnoKzEJXhjjOvRUgAz5nqHP9g";

        Driver driver = GraphDatabase.driver("neo4j://localhost:7617",
                AuthTokens.bearer(myToken),
                config = Config.builder().withLogging(Logging.console(Level.FINE)).build());


        try (Session session = driver.session(SessionConfig.builder().build())) {
            String greeting = session.writeTransaction(tx -> {
                Result result = tx.run("CREATE (a:Greeting) " +
                                "SET a.message = $message " +
                                "RETURN a.message + ', from node ' + id(a)",
                        parameters("message", "Hello"));
                return result.single().get(0).asString();
            });
            System.out.println(greeting);
        }
    }
    private static void impersonationSampleUsingUsernamePassword(String accessToken)  {

        Driver driver = GraphDatabase.driver("neo4j://localhost:7617",
                AuthTokens.basic("neo4j","Berlin99!"));

                //config = Config.builder().withLogging(Logging.console(Level.FINE)).build());


        try (Session session = driver.session(SessionConfig.builder().withImpersonatedUser("Bob").build())) {
            String greeting = session.writeTransaction(new TransactionWork<String>() {
                @Override
                public String execute(Transaction tx) {
                    Result result = tx.run("CREATE (a:Greeting) " +
                                    "SET a.message = $message " +
                                    "RETURN a.message + ', from node ' + id(a)",
                            parameters("message", "Hello"));
                    return result.single().get(0).asString();
                }
            });
            System.out.println(greeting);
        }
    }
    /**
     * Helper function unique to this sample setting. In a real application these wouldn't be so hardcoded, for example
     * different users may need different authority endpoints and the key/cert paths could come from a secure keyvault
     */
    private static void setUpSampleData() throws IOException {
        // Load properties file and set properties used throughout the sample
        Properties properties = new Properties();
        properties.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("application.properties"));
        authority = properties.getProperty("AUTHORITY");
        clientId = properties.getProperty("CLIENT_ID");
        keyPath = properties.getProperty("KEY_PATH");
        certPath = properties.getProperty("CERT_PATH");
        scope = properties.getProperty("SCOPE");
    }
}
