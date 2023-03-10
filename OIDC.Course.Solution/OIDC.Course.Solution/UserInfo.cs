namespace OIDC.Course.Solution;

public record UserInfo(
    bool IsAuthenticated,
    List<KeyValuePair<string, string>> Claims);