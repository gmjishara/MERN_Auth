import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import { logOut, setCredentials } from "../../features/auth/authSlice";

const baseQuery = fetchBaseQuery({
  baseUrl: "/",
  credentials: "include",
  prepareHeaders: (headers, { getState }) => {
    const token = getState().auth.token;

    // If we have a token set in state, let's assume that we should be passing it.
    if (token) {
      headers.set("authorization", `Bearer ${token}`);
    }

    return headers;
  },
});

const baseQueryWithReauth = async (args, api, extraOptions) => {
  let result = await baseQuery(args, api, extraOptions);
  if (result.error && result.error.status === 401) {
    // try to get a new token
    const refreshResult = await baseQuery(
      {
        url: "/auth/refreshToken",
        method: "POST",
      },
      api,
      extraOptions
    );
    if (refreshResult.data.token) {
      // store the new token
      api.dispatch(setCredentials(refreshResult.data.token));
      // retry the initial query
      result = await baseQuery(args, api, extraOptions);
    } else {
      api.dispatch(logOut());
    }
  }
  return result;
};

// initialize an empty api service that we'll inject endpoints into later as needed
export const apiSlice = createApi({
  reducerPath: "api",
  baseQuery: baseQueryWithReauth,
  endpoints: () => ({}),
  tagTypes: ["Post"],
});
