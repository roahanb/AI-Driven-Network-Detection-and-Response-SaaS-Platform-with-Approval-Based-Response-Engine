import { apiClient } from "./client";
import type { TokenResponse, User } from "@/types";

export const authApi = {
  login: (email: string, password: string) =>
    apiClient.post<TokenResponse>("/auth/login", { email, password }),

  register: (data: {
    email: string;
    full_name: string;
    password: string;
    organization_name: string;
  }) => apiClient.post<User>("/auth/register", data),

  refresh: (refresh_token: string) =>
    apiClient.post<TokenResponse>("/auth/refresh", { refresh_token }),

  me: () => apiClient.get<User>("/auth/me"),

  changePassword: (current_password: string, new_password: string) =>
    apiClient.post("/auth/change-password", { current_password, new_password }),
};
