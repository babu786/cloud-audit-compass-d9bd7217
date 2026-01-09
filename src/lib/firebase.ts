import { initializeApp, FirebaseApp } from 'firebase/app';
import { getAuth, Auth } from 'firebase/auth';
import { getFirestore, Firestore } from 'firebase/firestore';

interface FirebaseConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
}

const firebaseConfig: FirebaseConfig = {
  apiKey: "AIzaSyAJs7izoAZ9Z0yAR8HV9nu69b8XJ_tSRzU",
  authDomain: "cloud-audit-6f9ce.firebaseapp.com",
  projectId: "cloud-audit-6f9ce",
  storageBucket: "cloud-audit-6f9ce.firebasestorage.app",
  messagingSenderId: "469482454320",
  appId: "1:469482454320:web:b41c1dca8ebd9905589cf5",
};

export const app: FirebaseApp = initializeApp(firebaseConfig);
export const auth: Auth = getAuth(app);
export const db: Firestore = getFirestore(app);
