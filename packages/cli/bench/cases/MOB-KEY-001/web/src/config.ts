export const config = {
  api: import.meta.env.VITE_API_URL,
  adminKey: import.meta.env.VITE_ADMIN_API_KEY, // @hit
  signing: import.meta.env.VITE_SIGNING_SECRET, // @hit
  maps: import.meta.env.VITE_MAPS_PUBLIC_KEY,
};
