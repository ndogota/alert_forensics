/** @type {import('next').NextConfig} */
const nextConfig = {
  // Fully static export. The page reads the committed matrix file and the
  // committed recordings at build time and renders to plain HTML, CSS and JS
  // under out/, so the deployed page needs no server, no key and no fetch at
  // runtime. Vercel serves the static output directly.
  output: "export",
};

export default nextConfig;
