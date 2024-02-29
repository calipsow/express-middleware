"use strict";
const CHARS_INVALID = "CHARS_INVALID";
const CHARS_VALID = "CHARS_VALID";
const cl = (...args) => console.log(args);

function containsSpecialCharacters(str = "") {
  if (typeof str !== "string") return false;
  const regex = /[<>{}()"'\$\\]/;
  const hasSpecialCharacters = regex.test(str);
  if (hasSpecialCharacters) cl("found invalid chars:", str);
  return hasSpecialCharacters;
}

function softSpecialCharacterTest(str = "") {
  if (typeof str !== "string") return false;
  const regex = /[<>{}'\$\\]/;
  const hasSpecialCharacters = regex.test(str);
  if (hasSpecialCharacters) cl("found invalid chars:", str);
  return hasSpecialCharacters;
}

const secureHeaderStrings = (req) => {
  const headers = req.headers;
  let properties = Object.keys(headers);
  for (let i = 0; i < properties.length; i++) {
    let str = headers[properties[i]];
    if (!str) continue;
    if (softSpecialCharacterTest(str)) {
      cl("illegal chars in headers", properties[i]);
      return CHARS_INVALID;
    }
  }
  return CHARS_VALID;
};

const secureCookies = (req) => {
  if (!req.cookies) {
    cl("No cookies found");
    return CHARS_VALID;
  }

  const cookies = req.cookies;
  let cookieNames = Object.keys(cookies);

  for (let i = 0; i < cookieNames.length; i++) {
    let cookieValue = cookies[cookieNames[i]];
    if (!cookieValue) continue;
    if (containsSpecialCharacters(cookieValue)) {
      cl("Illegal chars in cookies");
      return CHARS_INVALID;
    }
  }
  return CHARS_VALID;
};

const secureBodyValues = (req) => {
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    cl("Request body is not an object or is empty");
    return CHARS_VALID; // Nichts zu überprüfen, wenn der Body leer oder kein Objekt ist
  }

  let keys = Object.keys(body);
  for (let i = 0; i < keys.length; i++) {
    let value = body[keys[i]];
    // Betrachten Sie nur String-Werte, da ungültige Zeichen in Strings gesucht werden
    if (typeof value === "string" && containsSpecialCharacters(value)) {
      cl("Illegal chars in request body values");
      return CHARS_INVALID;
    }
    // Rekursive Überprüfung für verschachtelte Objekte
    else if (typeof value === "object" && !Array.isArray(value)) {
      let result = secureBodyValues({ body: value });
      if (result === CHARS_INVALID) {
        return CHARS_INVALID;
      }
    }
  }
  return CHARS_VALID;
};

const secureUrlParams = (req) => {
  const params = req.params;
  if (!params || typeof params !== "object") {
    cl("No URL parameters found or params is not an object");
    return CHARS_VALID; // Keine URL-Parameter zu überprüfen
  }

  let paramKeys = Object.keys(params);
  for (let i = 0; i < paramKeys.length; i++) {
    let paramValue = params[paramKeys[i]];
    if (
      typeof paramValue === "string" &&
      containsSpecialCharacters(paramValue)
    ) {
      cl("Illegal chars in URL parameters");
      return CHARS_INVALID;
    }
  }
  return CHARS_VALID;
};

const secureQuery = (req) => {
  const query = req.query;
  if (!query || typeof query !== "object") {
    cl("No query parameters found or query is not an object");
    return CHARS_VALID; // Keine Query-Parameter zu überprüfen
  }

  let queryKeys = Object.keys(query);
  for (let i = 0; i < queryKeys.length; i++) {
    let queryValue = query[queryKeys[i]];
    // Query-Parameter können Arrays oder Strings sein
    if (Array.isArray(queryValue)) {
      for (let j = 0; j < queryValue.length; j++) {
        if (
          typeof queryValue[j] === "string" &&
          containsSpecialCharacters(queryValue[j])
        ) {
          cl("Illegal chars in query parameters");
          return CHARS_INVALID;
        }
      }
    } else if (
      typeof queryValue === "string" &&
      containsSpecialCharacters(queryValue)
    ) {
      cl("Illegal chars in query parameters");
      return CHARS_INVALID;
    }
  }
  return CHARS_VALID;
};

function secureRequest(req, res, next) {
  const method = req.method;
  let results = [];
  results.push(secureHeaderStrings(req));
  results.push(secureCookies(req));
  results.push(secureQuery(req));
  results.push(secureUrlParams(req));
  results.push(secureCookies(req));
  if (method !== "GET") results.push(secureBodyValues(req));

  if (results.includes(CHARS_INVALID)) {
    cl("Got suspicious request from:", req.ip);
    return res.status(400).send("bad request");
  }
  next();
}

module.exports = secureRequest;
