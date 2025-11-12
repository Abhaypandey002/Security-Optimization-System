import axios from "axios";

axios.defaults.baseURL = process.env.NEXT_PUBLIC_API_BASE_URL || "https://localhost:8443";
axios.defaults.withCredentials = false;

export default axios;
