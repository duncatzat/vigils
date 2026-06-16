import { createBrowserRouter, Navigate } from "react-router-dom";
import { PageShell } from "@/components/layout/PageShell";
import { ProtectionPage } from "@/features/protection/pages/ProtectionPage";
import { ApprovalsPage } from "@/features/approvals/pages/ApprovalsPage";
import { ActivityPage } from "@/features/activity/pages/ActivityPage";
import { SessionsPage } from "@/features/sessions/pages/SessionsPage";
import { ServersPage } from "@/features/servers/pages/ServersPage";
import { PrivacyPage } from "@/features/privacy/pages/PrivacyPage";
import { SandboxPage } from "@/features/sandbox/pages/SandboxPage";
import { SettingsPage } from "@/features/settings/pages/SettingsPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <PageShell />,
    children: [
      { index: true, element: <Navigate to="/protection" replace /> },
      { path: "protection", element: <ProtectionPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "activity", element: <ActivityPage /> },
      { path: "sessions", element: <SessionsPage /> },
      { path: "servers", element: <ServersPage /> },
      { path: "privacy", element: <PrivacyPage /> },
      { path: "sandbox", element: <SandboxPage /> },
      { path: "settings", element: <SettingsPage /> },
    ],
  },
]);
