import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { initializeFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyC_KVfLSD2jFo7kSUYQz30p4ZE7P_gAv7w",
  authDomain: "aegisquantum-54866.firebaseapp.com",
  databaseURL: "https://aegisquantum-54866-default-rtdb.europe-west1.firebasedatabase.app",
  projectId: "aegisquantum-54866",
  storageBucket: "aegisquantum-54866.firebasestorage.app",
  messagingSenderId: "718408070880",
  appId: "1:718408070880:web:882b41aedc011fa74c4285",
};

export const app  = initializeApp(firebaseConfig);
export const auth = getAuth(app);

// initializeFirestore avec experimentalAutoDetectLongPolling :
// corrige l'erreur CORS Safari (WebChannel bloque par la politique CORS stricte de Safari).
// Long-polling est utilise automatiquement quand WebSockets/fetch echouent.
export const db = initializeFirestore(app, {
  experimentalAutoDetectLongPolling: true,
});
