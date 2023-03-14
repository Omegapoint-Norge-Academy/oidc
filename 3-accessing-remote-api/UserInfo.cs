namespace OIDC.Course;

public record UserInfo(
    bool IsAuthenticated,
    List<KeyValuePair<string, string>> Claims);