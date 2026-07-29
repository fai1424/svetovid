import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
// Order matters: tokens.css (CSS variables) before globals (which @tailwind-expands them).
import "./styles/tokens.css";
import "./styles/globals.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
