<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Fixed security settings (handout section 2.3)
|--------------------------------------------------------------------------
| The instructor replaced the student-number seed (D1 / D2) with one set of
| values that every student uses. Where the handout says "seeded", use these.
| This file contains NO secrets, so it is committed to Git.
*/
const MIN_USERNAME_LENGTH   = 6;
const MAX_USERNAME_LENGTH   = 20;
const MIN_PASSWORD_LENGTH   = 8;
const MAX_PASSWORD_LENGTH   = 64;
const MAX_NAME_LENGTH       = 50;
const FORGOT_PASSWORD_AFTER = 2;      // failed log-ins before "Forgot Password?" appears
const LOCKOUT_TIER_1        = 15;     // seconds, after 3 consecutive failures
const LOCKOUT_TIER_2        = 30;     // seconds, after 6
const LOCKOUT_TIER_3        = 60;     // seconds, after 9
const OTP_EXPIRY_MINUTES    = 5;
const IDLE_TIMEOUT_MINUTES  = 15;
const IP_BLOCK_THRESHOLD    = 10;     // failures in 10 minutes, any account

/* Fixed rules from the handout (not seeded). */
const IP_BLOCK_WINDOW_MINUTES   = 10;
const IP_BLOCK_DURATION_MINUTES = 10;
const OTP_MAX_ATTEMPTS          = 3;
const OTP_RESEND_COOLDOWN       = 60;   // seconds
const OTP_MAX_RESENDS           = 3;    // per 15 minutes
const OTP_RESEND_WINDOW_MINUTES = 15;
const PASSWORD_HISTORY_LIMIT    = 3;
const IDLE_WARNING_SECONDS      = 60;
const RESET_AUTH_SECONDS        = 300;  // time allowed on Change Password

/* Name shown above the header on EVERY page (the approved system name). */
const APP_NAME = 'LIBRARY MANAGEMENT SYSTEM';
/* Used in the footer: (c) 2026 <OWNER_NAME>. All rights reserved. */
const OWNER_NAME = 'Eunice Ann S. Galon';

/*
| Authentication questions (section 5 question bank).
| The user PICKS 3 DIFFERENT questions at registration and answers each one.
*/
const QUESTION_BANK = [
    'Q1' => 'What was the name of your first pet?',
    'Q2' => 'Who was your best friend in elementary school?',
    'Q3' => 'Who was your favorite teacher in high school?',
    'Q4' => 'What is your mother\'s maiden first name?',
    'Q5' => 'What street did you live on in Grade 1?',
    'Q6' => 'What was the first song you learned by heart?',
    'Q7' => 'What was the name of your elementary school?',
    'Q8' => 'What dish did you cook for the first time?',
];
const REQUIRED_QUESTIONS = 3;

/* Only used by php/create_admin.php for admin / librarian accounts. */
const DEFAULT_STAFF_QUESTIONS = ['Q1', 'Q2', 'Q3'];

/* Dropdown lists for the library-specific registration fields. */
const PROGRAM_LIST = [
    'BS Information Technology',
    'BS Computer Science Engineering',
    'BS Electrical Engineering',
    'Other',
];
const YEAR_LEVEL_LIST = ['1st Year', '2nd Year', '3rd Year', '4th Year', '5th Year'];
const STUDENT_STATUS_LIST = ['Currently Enrolled', 'On Leave'];
const ENROLLED_STATUS = 'Currently Enrolled';
const ROMAN_EXTENSIONS = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X'];
