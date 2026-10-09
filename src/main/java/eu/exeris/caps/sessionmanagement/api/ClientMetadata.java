package eu.exeris.caps.sessionmanagement.api;

/**
 * Client environment attributes captured at session establishment or token rotation.
 *
 * @param userAgent user-agent header string or client identifier
 * @param ipAddress client IP address
 * @since 0.1.0
 */
public record ClientMetadata(
        String userAgent,
        String ipAddress
) {

    public ClientMetadata {
        if (userAgent != null && userAgent.length() > 512) {
            userAgent = userAgent.substring(0, 512);
        }
        if (ipAddress != null && ipAddress.length() > 64) {
            ipAddress = ipAddress.substring(0, 64);
        }
    }

    public static final ClientMetadata EMPTY = new ClientMetadata(null, null);

    public static ClientMetadata of(String userAgent, String ipAddress) {
        return new ClientMetadata(userAgent, ipAddress);
    }

    public static ClientMetadata empty() {
        return EMPTY;
    }
}
