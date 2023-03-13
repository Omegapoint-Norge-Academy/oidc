import React from "react";
import { useLocation } from "react-router-dom";

export function Authentication() {
    const location = useLocation();

    return <div>
        <a href={`client/account/login?returnUrl=${location.pathname}`}>click here to login</a>
        <p></p>
        <a href="client/account/logout">click here to logout</a>
    </div>
}