import { useAuthContext } from "../auth/useAuthContext";
import React from "react";

export function Authentication() {
    const context = useAuthContext();
    return context?.user?.isAuthenticated
        ? <a href="https://localhost:5001/client/account/logout">click here to logout (logged in as {context?.user?.claims['name']})</a>
        : <a href="https://localhost:5001/client/account/login">click here to login</a>;
}