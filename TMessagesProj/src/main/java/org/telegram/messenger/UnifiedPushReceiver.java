package org.telegram.messenger;

import android.content.Context;
import android.os.SystemClock;
import android.util.Base64;

import androidx.annotation.NonNull;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.json.JSONStringer;
import org.telegram.tgnet.ConnectionsManager;

import org.unifiedpush.android.connector.FailedReason;
import org.unifiedpush.android.connector.PushService;
import org.unifiedpush.android.connector.UnifiedPush;
import org.unifiedpush.android.connector.data.PushEndpoint;
import org.unifiedpush.android.connector.data.PushMessage;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import xyz.nextalone.nagram.NaConfig;

public class UnifiedPushReceiver extends PushService {

    @Override
    public void onNewEndpoint(@NonNull PushEndpoint endpoint, @NonNull String instance){
        Utilities.globalQueue.postRunnable(() -> {
            String jsonToken;
            SharedConfig.pushStringGetTimeEnd = SystemClock.elapsedRealtime();

            String savedDistributor = UnifiedPush.getSavedDistributor(ApplicationLoader.applicationContext);

            if (!endpoint.equals(SharedConfig.pushString)) {
                // Generate ECDH Keypair on P-256 curve
                KeyPairGenerator ecdhKeyPairGenerator;
                try {
                    ecdhKeyPairGenerator = KeyPairGenerator.getInstance("EC");
                    ecdhKeyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
                } catch (Throwable exception) {
                    FileLog.e(exception);
                    return;
                }
                KeyPair ecdhKeyPair = ecdhKeyPairGenerator.generateKeyPair();
                SharedConfig.pushAuthKey = ecdhKeyPair.getPrivate().getEncoded();
                SharedConfig.pushAuthPubKey = ecdhKeyPair.getPublic().getEncoded();
                // Generate auth secret
                SharedConfig.pushAuthSecret = new byte[16];
                Utilities.random.nextBytes(SharedConfig.pushAuthSecret);
                SharedConfig.saveConfig();

                try {
                    jsonToken = new JSONStringer()
                            .object()
                            .key("endpoint").value(endpoint)
                            .key("keys")
                            .object()
                            .key("p256dh").value(Base64.encodeToString(convertECPubkeyToUncompressedOctetStream((ECPublicKey) ecdhKeyPair.getPublic()), Base64.URL_SAFE | Base64.NO_WRAP))
                            .key("auth").value(Base64.encodeToString(SharedConfig.pushAuthSecret, Base64.URL_SAFE | Base64.NO_WRAP))
                            .endObject()
                            .endObject()
                            .toString();
                } catch (Throwable exception) {
                    FileLog.e(exception);
                    return;
                }
            }  else {
                try {
                    final KeyFactory ECKeyFactory = KeyFactory.getInstance("EC");
                    ECPublicKey pubKey = (ECPublicKey) ECKeyFactory.generatePublic(new X509EncodedKeySpec(SharedConfig.pushAuthPubKey));

                    jsonToken = new JSONStringer()
                            .object()
                            .key("endpoint").value(endpoint)
                            .key("keys")
                            .object()
                            .key("p256dh").value(Base64.encodeToString(convertECPubkeyToUncompressedOctetStream(pubKey), Base64.URL_SAFE | Base64.NO_WRAP))
                            .key("auth").value(Base64.encodeToString(SharedConfig.pushAuthSecret, Base64.URL_SAFE | Base64.NO_WRAP))
                            .endObject()
                            .endObject()
                            .toString();
                } catch (Throwable exception) {
                    FileLog.e(exception);
                    return;
                }
            }

            PushListenerController.sendRegistrationToServer(PushListenerController.PUSH_TYPE_WEBPUSH, jsonToken);
        });
    }

    @Override
    public void onMessage(@NonNull PushMessage message, @NonNull String instance){
        final long receiveTime = SystemClock.elapsedRealtime();

        final byte[] content = message.getContent();
        Map<String, String> data = decodePushData(content);

        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("UnifiedPush received data: " + data + " from instance: " + instance);
        }

        PushListenerController.processRemoteMessage(PushListenerController.PUSH_TYPE_WEBPUSH, data.get("p"), receiveTime);
    }

    @Override
    public void onRegistrationFailed(@NonNull FailedReason failedReason, @NonNull String instance){
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Failed to get endpoint");
        }
        SharedConfig.pushStringStatus = "__UNIFIEDPUSH_FAILED__";
        Utilities.globalQueue.postRunnable(() -> {
            SharedConfig.pushStringGetTimeEnd = SystemClock.elapsedRealtime();

            PushListenerController.sendRegistrationToServer(PushListenerController.PUSH_TYPE_WEBPUSH, null);
        });
    }

    @Override
    public void onUnregistered(@NonNull String instance) {
        SharedConfig.pushStringStatus = "__UNIFIEDPUSH_FAILED__";
        Utilities.globalQueue.postRunnable(() -> {
            SharedConfig.pushStringGetTimeEnd = SystemClock.elapsedRealtime();

            PushListenerController.sendRegistrationToServer(PushListenerController.PUSH_TYPE_WEBPUSH, null);
        });
    }

    static private Map<String, String> decodePushData(byte[] content) {
        if (content == null || content.length == 0) {
            return new HashMap<>();
        }

        String jsonString = new String(content, StandardCharsets.UTF_8); // UTF-8

        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, String>>() {}.getType();

        try {
            return gson.fromJson(jsonString, mapType);
        } catch (com.google.gson.JsonSyntaxException e) {
            FileLog.e("Failed to parse JSON: " + e.getMessage());
            FileLog.e("JSON String: " + jsonString);
            return new HashMap<>();
        }
    }

    static final private ECParameterSpec P256CurveSpec = new ECParameterSpec(
            new EllipticCurve(
                    new ECFieldFp(new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
                    new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
                    new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")
            ),
            new ECPoint(
                    new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                    new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
            ),
            new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"), 0x1
    );
    static final private int ECCoordinateSize = (((ECFieldFp) P256CurveSpec.getCurve().getField()).getP().subtract(BigInteger.ONE).bitLength() + 7) / 8;
    private static byte[] convertECPubkeyToUncompressedOctetStream(ECPublicKey pubkey) {
        final byte[] stream = new byte[2 * ECCoordinateSize + 1];
        final ECPoint pubkeyCurvePoint = pubkey.getW();
        final byte[] pointX = pubkeyCurvePoint.getAffineX().toByteArray();
        final byte[] pointY = pubkeyCurvePoint.getAffineY().toByteArray();
        System.arraycopy(pointX, 0, stream, 1 + ECCoordinateSize - pointX.length, pointX.length);
        System.arraycopy(pointY, 0, stream, 1 + 2 * ECCoordinateSize - pointY.length, pointY.length);
        stream[0] = 0x04;
        return stream;
    }
}
