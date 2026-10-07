import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { RequireAuth } from "./auth/RequireAuth";
import { LoadingBlock } from "./components/ui/States";
import { AppLayout } from "./layouts/AppLayout";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Payloads = lazy(() => import("./pages/Payloads"));
const Login = lazy(() => import("./pages/Login"));
const NotFound = lazy(() => import("./pages/NotFound"));

export default function App() {
  return (
    <Suspense fallback={<LoadingBlock rows={6} />}>
      <Routes>
        <Route path="login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="payloads" element={<Payloads />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}
