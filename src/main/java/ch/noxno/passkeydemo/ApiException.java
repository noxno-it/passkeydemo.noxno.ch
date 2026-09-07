package ch.noxno.passkeydemo;

/**
 * Every passkey policy failure. Always answered with HTTP 403 and the body
 * {"message": "&lt;German text&gt;", "errors": ["&lt;CODE&gt;"]} so the app's HTTP interceptor
 * does not surface it a second time.
 */
public class ApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public static final String PASSKEY_REQUIRED = "PASSKEY_REQUIRED";
    public static final String FULL_LOGIN_REQUIRED = "FULL_LOGIN_REQUIRED";
    public static final String CEREMONY_EXPIRED = "CEREMONY_EXPIRED";
    public static final String CEREMONY_CONSUMED = "CEREMONY_CONSUMED";
    public static final String ATTESTATION_REJECTED = "ATTESTATION_REJECTED";
    public static final String DEVICE_NOT_ELIGIBLE = "DEVICE_NOT_ELIGIBLE";
    public static final String CREDENTIAL_UNKNOWN = "CREDENTIAL_UNKNOWN";
    public static final String COUNTER_REGRESSION = "COUNTER_REGRESSION";
    public static final String PASSWORD_INVALID = "PASSWORD_INVALID";
    public static final String RATE_LIMITED = "RATE_LIMITED";

    private final String code;

    public ApiException(String code, String germanMessage) {
        super(germanMessage);
        this.code = code;
    }

    public ApiException(String code, String germanMessage, Throwable cause) {
        super(germanMessage, cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static ApiException passkeyRequired() {
        return new ApiException(PASSKEY_REQUIRED,
                "Für dieses Konto ist ein Passkey eingerichtet. Bitte melde Dich mit dem Passkey an.");
    }

    public static ApiException fullLoginRequired() {
        return new ApiException(FULL_LOGIN_REQUIRED,
                "Die letzte vollständige Anmeldung ist zu lange her. Bitte melde Dich mit Passwort und Passkey an.");
    }

    public static ApiException ceremonyExpired() {
        return new ApiException(CEREMONY_EXPIRED, "Die Anfrage ist abgelaufen. Bitte versuche es erneut.");
    }

    public static ApiException ceremonyConsumed() {
        return new ApiException(CEREMONY_CONSUMED, "Die Anfrage wurde bereits verwendet. Bitte versuche es erneut.");
    }

    public static ApiException attestationRejected(String detail) {
        return new ApiException(ATTESTATION_REJECTED, "Der Passkey konnte nicht bestätigt werden: " + detail);
    }

    public static ApiException attestationRejected(String detail, Throwable cause) {
        return new ApiException(ATTESTATION_REJECTED, "Der Passkey konnte nicht bestätigt werden: " + detail, cause);
    }

    public static ApiException deviceNotEligible(String detail) {
        return new ApiException(DEVICE_NOT_ELIGIBLE, "Dieses Gerät ist für Passkeys nicht geeignet: " + detail);
    }

    public static ApiException credentialUnknown() {
        return new ApiException(CREDENTIAL_UNKNOWN, "Dieser Passkey ist auf dem Server nicht bekannt.");
    }

    public static ApiException counterRegression() {
        return new ApiException(COUNTER_REGRESSION, "Der Zähler des Passkeys ist nicht gewachsen.");
    }

    public static ApiException passwordInvalid() {
        return new ApiException(PASSWORD_INVALID, "E-Mail-Adresse oder Passwort ist falsch.");
    }

    public static ApiException rateLimited() {
        return new ApiException(RATE_LIMITED, "Zu viele Anfragen. Bitte versuche es später erneut.");
    }
}
