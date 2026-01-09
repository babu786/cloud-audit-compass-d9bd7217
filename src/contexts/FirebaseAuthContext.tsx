import React, { createContext, useContext, useEffect, useState } from 'react';
import { 
  User, 
  onAuthStateChanged, 
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  signOut as firebaseSignOut,
  sendEmailVerification
} from 'firebase/auth';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { auth, db } from '@/lib/firebase';

interface UserProfile {
  id: string;
  email: string | null;
  full_name: string | null;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

interface FirebaseAuthContextType {
  user: User | null;
  profile: UserProfile | null;
  loading: boolean;
  emailVerified: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string, fullName: string) => Promise<void>;
  signOut: () => Promise<void>;
  resendVerificationEmail: () => Promise<void>;
}

const FirebaseAuthContext = createContext<FirebaseAuthContextType | undefined>(undefined);

export function FirebaseAuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchOrCreateProfile = async (firebaseUser: User): Promise<void> => {
    const profileRef = doc(db, 'profiles', firebaseUser.uid);
    const profileSnap = await getDoc(profileRef);

    if (profileSnap.exists()) {
      const data = profileSnap.data();
      setProfile({
        id: firebaseUser.uid,
        email: data.email || firebaseUser.email,
        full_name: data.full_name || firebaseUser.displayName,
        avatar_url: data.avatar_url || firebaseUser.photoURL,
        created_at: data.created_at,
        updated_at: data.updated_at,
      });
    } else {
      const now = new Date().toISOString();
      const newProfile: UserProfile = {
        id: firebaseUser.uid,
        email: firebaseUser.email,
        full_name: firebaseUser.displayName,
        avatar_url: firebaseUser.photoURL,
        created_at: now,
        updated_at: now,
      };
      await setDoc(profileRef, newProfile);
      setProfile(newProfile);
    }
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      
      if (firebaseUser) {
        try {
          await fetchOrCreateProfile(firebaseUser);
        } catch (error) {
          console.error('Error fetching/creating profile:', error);
        }
      } else {
        setProfile(null);
      }
      
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signIn = async (email: string, password: string): Promise<void> => {
    await signInWithEmailAndPassword(auth, email, password);
  };

  const signUp = async (email: string, password: string, fullName: string): Promise<void> => {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    await updateProfile(userCredential.user, { displayName: fullName });
    // Send verification email after signup
    await sendEmailVerification(userCredential.user);
  };

  const resendVerificationEmail = async (): Promise<void> => {
    if (user && !user.emailVerified) {
      await sendEmailVerification(user);
    }
  };

  const signOut = async (): Promise<void> => {
    await firebaseSignOut(auth);
    setUser(null);
    setProfile(null);
  };

  return (
    <FirebaseAuthContext.Provider
      value={{
        user,
        profile,
        loading,
        emailVerified: user?.emailVerified ?? false,
        signIn,
        signUp,
        signOut,
        resendVerificationEmail,
      }}
    >
      {children}
    </FirebaseAuthContext.Provider>
  );
}

export function useFirebaseAuth() {
  const context = useContext(FirebaseAuthContext);
  if (context === undefined) {
    throw new Error('useFirebaseAuth must be used within a FirebaseAuthProvider');
  }
  return context;
}
