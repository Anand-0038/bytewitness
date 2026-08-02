import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "@fontsource/bricolage-grotesque/latin-400.css";
import "@fontsource/bricolage-grotesque/latin-500.css";
import "@fontsource/bricolage-grotesque/latin-600.css";
import "@fontsource/bricolage-grotesque/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "./styles.css";

const rootElement = document.getElementById("root");

if (!rootElement) throw new Error("ByteWitness could not find its application root.");

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
