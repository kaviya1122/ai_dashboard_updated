/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  Lock,
  Mail,
  User,
  CheckCircle2,
  AlertCircle,
  Eye,
  EyeOff,
  ArrowRight,
  UserPlus,
  LogIn,
  Check,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Login: React.FC = () => {
  const { login, register } = useSecurity();
  const navigate = useNavigate();
  const location = useLocation();

  // Mode: 'login' or 'register'
  const [mode, setMode] = useState<'login' | 'register'>('login');

  // Form Fields
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState('Security Analyst');

  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const resetMessages = () => {
    setErrorMessage(null);
    setSuccessMessage(null);
  };

  const handleModeChange = (newMode: 'login' | 'register') => {
    setMode(newMode);
    resetMessages();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    resetMessages();

    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !cleanEmail.includes('@')) {
      setErrorMessage('Please enter a valid email address.');
      return;
    }

    if (!password) {
      setErrorMessage('Please enter your password.');
      return;
    }

    setIsSubmitting(true);

    if (mode === 'register') {
      // Validate registration
      if (password.length < 6) {
        setErrorMessage('Password must be at least 6 characters long.');
        setIsSubmitting(false);
        return;
      }

      if (password !== confirmPassword) {
        setErrorMessage('Passwords do not match. Please re-type your password.');
        setIsSubmitting(false);
        return;
      }

      const res = await register(cleanEmail, password, fullName, role);
      setIsSubmitting(false);

      if (res.success) {
        setSuccessMessage('Account created successfully! Redirecting to your dashboard...');
        setTimeout(() => {
          const from = (location.state as { from?: string })?.from || '/';
          navigate(from, { replace: true });
        }, 600);
      } else {
        setErrorMessage(res.error || 'Failed to create account.');
      }
    } else {
      // Sign In
      const res = await login(cleanEmail, password);
      setIsSubmitting(false);

      if (res.success) {
        const from = (location.state as { from?: string })?.from || '/';
        navigate(from, { replace: true });
      } else {
        setErrorMessage(res.error || 'Failed to sign in. Please verify your credentials.');
      }
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col justify-center items-center p-4 selection:bg-cyan-900 selection:text-cyan-100 font-sans">
      <div className="w-full max-w-md space-y-6">
        {/* App Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 items-center justify-center shadow-lg shadow-cyan-950/40 border border-cyan-500/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
              AI Security Dashboard
            </h1>
            <p className="text-xs text-zinc-400 mt-1">
              Simple, reliable threat protection & security workspace
            </p>
          </div>
        </div>

        {/* Auth Mode Toggle Tabs */}
        <div className="flex rounded-lg bg-zinc-900 border border-zinc-800 p-1">
          <button
            type="button"
            onClick={() => handleModeChange('login')}
            className={`flex-1 py-2 text-xs font-semibold rounded-md transition-all flex items-center justify-center gap-1.5 ${
              mode === 'login'
                ? 'bg-zinc-800 text-cyan-400 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <LogIn className="w-3.5 h-3.5" />
            <span>Sign In</span>
          </button>

          <button
            type="button"
            onClick={() => handleModeChange('register')}
            className={`flex-1 py-2 text-xs font-semibold rounded-md transition-all flex items-center justify-center gap-1.5 ${
              mode === 'register'
                ? 'bg-zinc-800 text-cyan-400 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <UserPlus className="w-3.5 h-3.5" />
            <span>Create Account</span>
          </button>
        </div>

        {/* Card Form */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-6 shadow-2xl space-y-5">
          <div className="border-b border-zinc-800 pb-3">
            <h2 className="text-sm font-bold text-zinc-100">
              {mode === 'login' ? 'Sign in to your account' : 'Create your security profile'}
            </h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              {mode === 'login'
                ? 'Enter your email and password to access the dashboard'
                : 'Each email can only be used to create one account'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {/* If Register: Full Name */}
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300">Full Name</label>
                <div className="relative">
                  <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="e.g. Kaviya T"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2.5 pl-9 pr-3 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 text-xs"
                  />
                </div>
              </div>
            )}

            {/* Email Field */}
            <div className="space-y-1">
              <label className="font-semibold text-zinc-300">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@example.com"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2.5 pl-9 pr-3 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 text-xs"
                />
              </div>
            </div>

            {/* If Register: Role / Position */}
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300">Your Role / Job Title</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2 px-3 text-zinc-200 text-xs focus:outline-none focus:border-cyan-500"
                >
                  <option value="Security Analyst">Security Analyst</option>
                  <option value="Security Manager">Security Manager</option>
                  <option value="System Administrator">System Administrator</option>
                  <option value="Software Developer">Software Developer</option>
                  <option value="IT Specialist">IT Specialist</option>
                  <option value="Personal User">Personal User</option>
                </select>
              </div>
            )}

            {/* Password */}
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="font-semibold text-zinc-300">Password</label>
                {mode === 'register' && (
                  <span className="text-[10px] text-zinc-500">Min. 6 characters</span>
                )}
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2.5 pl-9 pr-9 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 text-xs"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password if Register */}
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300">Confirm Password</label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter password"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-md py-2.5 pl-9 pr-3 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 text-xs"
                  />
                </div>
              </div>
            )}

            {/* Error Message */}
            {errorMessage && (
              <div className="p-3 rounded-lg bg-red-950/70 border border-red-800/80 text-xs text-red-200 space-y-1.5">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <p className="leading-relaxed">{errorMessage}</p>
                </div>
                {errorMessage.includes('already exists') && (
                  <button
                    type="button"
                    onClick={() => handleModeChange('login')}
                    className="text-xs font-semibold text-cyan-300 underline hover:text-cyan-200 block pl-6"
                  >
                    Click here to Sign In with this email →
                  </button>
                )}
                {errorMessage.includes('No account found') && (
                  <button
                    type="button"
                    onClick={() => handleModeChange('register')}
                    className="text-xs font-semibold text-cyan-300 underline hover:text-cyan-200 block pl-6"
                  >
                    Click here to Create an Account →
                  </button>
                )}
              </div>
            )}

            {/* Success Message */}
            {successMessage && (
              <div className="p-3 rounded-lg bg-emerald-950/70 border border-emerald-800/80 text-xs text-emerald-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{successMessage}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white font-semibold tracking-wide transition-all duration-150 flex items-center justify-center gap-2 shadow-md shadow-cyan-950/50 disabled:opacity-50 text-xs cursor-pointer"
            >
              <span>
                {isSubmitting
                  ? mode === 'login'
                    ? 'Signing in...'
                    : 'Creating Account...'
                  : mode === 'login'
                  ? 'Sign In to Dashboard'
                  : 'Create Account & Enter'}
              </span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Bottom Switch Note */}
          <div className="pt-3 border-t border-zinc-800 text-center text-xs text-zinc-400">
            {mode === 'login' ? (
              <p>
                Don't have an account yet?{' '}
                <button
                  type="button"
                  onClick={() => handleModeChange('register')}
                  className="font-semibold text-cyan-400 hover:underline cursor-pointer"
                >
                  Create one now
                </button>
              </p>
            ) : (
              <p>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => handleModeChange('login')}
                  className="font-semibold text-cyan-400 hover:underline cursor-pointer"
                >
                  Sign in instead
                </button>
              </p>
            )}
          </div>
        </div>

        {/* Simple friendly feature checklist */}
        <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl p-4 text-xs text-zinc-400 space-y-2">
          <span className="font-semibold text-zinc-200 block">Everything you need in one place:</span>
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="flex items-center gap-1.5 text-zinc-300">
              <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>100MB File Scanner</span>
            </div>
            <div className="flex items-center gap-1.5 text-zinc-300">
              <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Easy Visual Diagrams</span>
            </div>
            <div className="flex items-center gap-1.5 text-zinc-300">
              <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Instant Threat Alerts</span>
            </div>
            <div className="flex items-center gap-1.5 text-zinc-300">
              <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Secure Cloud Storage</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
