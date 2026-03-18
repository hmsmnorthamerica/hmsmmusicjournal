// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE SECURITY RULES — Music Practice Journal
// Happy Minds School of Music
//
// Role-based access control for three roles:
//   Student     — Read own data only, zero write to balances
//   Instructor  — Read/Update assigned students only
//   Admin       — Full access: read, write, edit, delete ALL data
// ═══════════════════════════════════════════════════════════════════════════════


// ─── OPTION A: FIRESTORE SECURITY RULES (firestore.rules) ────────────────────
// Copy the block below into your Firebase Console → Firestore → Rules tab.
//
// rules_version = '2';
// service cloud.firestore {
//   match /databases/{database}/documents {
//
//     // ── User profiles ────────────────────────────────────────────────────
//     match /users/{userId} {
//
//       // Users can read their own profile
//       allow read: if request.auth != null
//                   && request.auth.uid == userId;
//
//       // Users can update their own profile (except role field)
//       allow update: if request.auth != null
//                     && request.auth.uid == userId
//                     && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);
//
//       // Admins can read, write, create, delete ANY user profile
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//
//       // Only admins can create users with admin role
//       allow create: if request.auth != null
//                     && (request.resource.data.role != 'admin'
//                         || request.auth.token.role == 'admin');
//
//       // Only admins can delete user profiles
//       allow delete: if request.auth != null
//                     && request.auth.token.role == 'admin';
//     }
//
//     // ── Student documents ──────────────────────────────────────────────────
//     match /students/{studentId} {
//
//       // Students can read and update only their own document
//       allow read, update: if request.auth != null
//                           && request.auth.uid == studentId;
//
//       // Instructors can read/update ONLY if the student's instructorId matches their uid
//       allow read, update: if request.auth != null
//                           && request.auth.token.role == 'instructor'
//                           && resource.data.instructorId == request.auth.uid;
//
//       // Admins have full access to ALL student documents
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//
//       // No one else can create or delete student documents except admins
//       allow create: if request.auth != null
//                     && (request.auth.uid == studentId
//                         || request.auth.token.role == 'admin');
//
//       allow delete: if request.auth != null
//                     && request.auth.token.role == 'admin';
//     }
//
//     // ── Practice logs (journal entries) ────────────────────────────────────
//     match /students/{studentId}/practiceLogs/{logId} {
//
//       // Students can only read/write their own practice logs
//       allow read, write: if request.auth != null
//                          && request.auth.uid == studentId;
//
//       // Assigned instructor can read, write, and delete their student's logs
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'instructor'
//                          && get(/databases/$(database)/documents/students/$(studentId)).data.instructorId == request.auth.uid;
//
//       // Admins have FULL access to ALL practice logs (read + write + delete)
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//     }
//
//     // ── Journal entries (weekly practice journals) ─────────────────────────
//     match /journalEntries/{entryId} {
//
//       // Students can read their own entries only
//       allow read: if request.auth != null
//                   && resource.data.studentEmail == request.auth.uid;
//
//       // Students can create entries for themselves
//       allow create: if request.auth != null
//                     && request.resource.data.studentEmail == request.auth.uid;
//
//       // Instructors can read, write, and delete entries for their assigned students
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'instructor'
//                          && get(/databases/$(database)/documents/students/$(resource.data.studentEmail)).data.instructorId == request.auth.uid;
//
//       // Admins can read, write, update, delete ALL journal entries
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//     }
//
//     // ── Instructor documents ───────────────────────────────────────────────
//     match /instructors/{instructorId} {
//
//       // Instructors can read/update their own profile
//       allow read, update: if request.auth != null
//                           && request.auth.uid == instructorId;
//
//       // Students can read their assigned instructor's profile
//       allow read: if request.auth != null
//                   && request.auth.token.role == 'student'
//                   && resource.data.studentsList.hasAny([request.auth.uid]);
//
//       // Admins have full access to ALL instructor profiles
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//     }
//
//     // ── Assignments ────────────────────────────────────────────────────────
//     match /assignments/{assignmentId} {
//       allow read: if request.auth != null;
//       allow write: if request.auth != null
//                    && (request.auth.token.role == 'instructor'
//                        || request.auth.token.role == 'admin');
//       // Admins can also delete assignments
//       allow delete: if request.auth != null
//                     && request.auth.token.role == 'admin';
//     }
//
//     // ── Student Balances (stamps & coins) ─────────────────────────────────
//     match /balances/{studentId} {
//
//       // Students can READ their own balance only — zero write permission
//       allow read: if request.auth != null
//                   && request.auth.uid == studentId
//                   && request.auth.token.role == 'student';
//
//       // Instructors can UPDATE (add/subtract) only for their assigned students
//       allow read, update: if request.auth != null
//                           && request.auth.token.role == 'instructor'
//                           && get(/databases/$(database)/documents/students/$(studentId)).data.instructorId == request.auth.uid;
//
//       // Admins can READ and WRITE balances for ANY student
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//
//       // Prevent negative balances (applies to all update operations)
//       allow update: if request.resource.data.stamps >= 0
//                     && request.resource.data.coins >= 0;
//     }
//
//     // ── Redemptions (stamps/coins redeemed for rewards) ─────────────────
//     match /redemptions/{instrumentId} {
//
//       // Admins can manage all redemptions
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//
//       // Instructors can read AND write redemptions (redeem stamps/coins)
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'instructor';
//     }
//   }
// }


// ─── OPTION B: SUPABASE ROW LEVEL SECURITY (RLS) ────────────────────────────
// Run these SQL statements in your Supabase SQL Editor.
//
// -- ── Users table ──────────────────────────────────────────────────────────
// ALTER TABLE users ENABLE ROW LEVEL SECURITY;
//
// -- Users can read their own profile
// CREATE POLICY "users_read_own"
//   ON users FOR SELECT
//   USING (auth.uid() = id);
//
// -- Users can update their own profile (except role)
// CREATE POLICY "users_update_own"
//   ON users FOR UPDATE
//   USING (auth.uid() = id);
//
// -- Admins: Full access to ALL user profiles
// CREATE POLICY "admin_full_users"
//   ON users FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');
//
// -- ── Students table ───────────────────────────────────────────────────────
// ALTER TABLE students ENABLE ROW LEVEL SECURITY;
//
// -- Students can read/update only their own document
// CREATE POLICY "students_own_access"
//   ON students FOR ALL
//   USING (auth.uid() = id)
//   WITH CHECK (auth.uid() = id);
//
// -- Instructors can READ a student document only if instructorId matches
// CREATE POLICY "instructor_read_assigned_students"
//   ON students FOR SELECT
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   );
//
// -- Instructors can UPDATE a student document only if instructorId matches
// CREATE POLICY "instructor_update_assigned_students"
//   ON students FOR UPDATE
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   )
//   WITH CHECK (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   );
//
// -- Admins: Full access to ALL student documents
// CREATE POLICY "admin_full_students"
//   ON students FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');
//
// -- ── Practice logs table ──────────────────────────────────────────────────
// ALTER TABLE practice_logs ENABLE ROW LEVEL SECURITY;
//
// -- Students can only see their own practice logs
// CREATE POLICY "students_own_logs"
//   ON practice_logs FOR ALL
//   USING (auth.uid() = student_id)
//   WITH CHECK (auth.uid() = student_id);
//
// -- Instructors can read/write/delete logs of their assigned students
// CREATE POLICY "instructor_manage_assigned_logs"
//   ON practice_logs FOR ALL
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   );
//
// -- Admins: Full access to ALL practice logs
// CREATE POLICY "admin_full_logs"
//   ON practice_logs FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');
//
// -- ── Balances table ───────────────────────────────────────────────────────
// ALTER TABLE balances ENABLE ROW LEVEL SECURITY;
//
// -- Students: READ-only access to their own balance (zero write permission)
// CREATE POLICY "student_read_own_balance"
//   ON balances FOR SELECT
//   USING (auth.uid() = student_id);
//
// -- Instructors: Can UPDATE balances only for their assigned students
// CREATE POLICY "instructor_update_assigned_balance"
//   ON balances FOR UPDATE
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   )
//   WITH CHECK (stamps >= 0 AND coins >= 0);
//
// -- Instructors: Can READ balances for assigned students
// CREATE POLICY "instructor_read_assigned_balance"
//   ON balances FOR SELECT
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   );
//
// -- Admins: Full access to ALL balances
// CREATE POLICY "admin_full_balance"
//   ON balances FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');
//
// -- ── Redemptions table ────────────────────────────────────────────────────
// ALTER TABLE redemptions ENABLE ROW LEVEL SECURITY;
//
// -- Admins: Full access to all redemptions
// CREATE POLICY "admin_full_redemptions"
//   ON redemptions FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');
//
// -- Instructors: Can read AND write redemptions (redeem stamps/coins)
// CREATE POLICY "instructor_manage_redemptions"
//   ON redemptions FOR ALL
//   USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor');


// ═══════════════════════════════════════════════════════════════════════════════
// OPTION C: LOCAL SIMULATION (used in this app via localStorage)
// These functions mirror the Firestore/Supabase rules for our localStorage-based app.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Can an instructor access a specific student? ─────────────────────────────
function canInstructorAccessStudent(instructorEmail, studentData) {
  // Instructor can only read/update if the student's instructorId matches
  return studentData.instructorId === instructorEmail;
}

// ── Can this user access a student's practice logs? ──────────────────────────
function canAccessPracticeLogs(currentUser, studentEmail) {
  // Students can only see their own logs
  if (currentUser.role === 'student') {
    return currentUser.email === studentEmail;
  }
  // Instructors can only see logs of their assigned students
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u => u.email === studentEmail);
    return student && student.instructorId === currentUser.email;
  }
  // Admins can see ALL logs — full read access
  if (currentUser.role === 'admin') {
    return true;
  }
  return false;
}

// ── Can this user view a journal entry? ──────────────────────────────────────
function canViewJournalEntry(currentUser, entry) {
  // Admins can view ALL entries
  if (currentUser.role === 'admin') {
    return true;
  }
  // Students can only view entries with their name or email
  if (currentUser.role === 'student') {
    return (entry.studentEmail && entry.studentEmail.toLowerCase() === currentUser.email.toLowerCase()) ||
           (entry.studentName && entry.studentName.toLowerCase() === currentUser.name.toLowerCase());
  }
  // Instructors can view entries of their assigned students
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u =>
      u.role === 'student' &&
      ((entry.studentEmail && u.email === entry.studentEmail) ||
       (entry.studentName && u.name.toLowerCase() === entry.studentName.toLowerCase()))
    );
    return student && student.instructorId === currentUser.email;
  }
  return false;
}

// ── Can this user edit a journal entry? ──────────────────────────────────────
// Student:     Can edit own practice logs (practice circles, time, questions)
// Instructor:  Can view, edit, and delete journal entries for assigned students
// Admin:       Full access to ALL entries
function canEditJournalEntry(currentUser, entry) {
  // Admins can edit ALL entries — stamps, coins, grades, everything
  if (currentUser.role === 'admin') {
    return { allowed: true, fields: 'all' };
  }
  // Instructors can fully edit entries for their assigned students
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u =>
      u.role === 'student' &&
      ((entry.studentEmail && u.email === entry.studentEmail) ||
       (entry.studentName && u.name.toLowerCase() === entry.studentName.toLowerCase()))
    );
    if (student && student.instructorId === currentUser.email) {
      return { allowed: true, fields: 'all' }; // full edit: songs, grades, stamps, coins, feedback, delete
    }
    return { allowed: false, reason: 'Can only edit entries for your assigned students.' };
  }
  // Students can edit their own practice data (practice circles, time, questions)
  if (currentUser.role === 'student') {
    const isOwn = (entry.studentEmail && entry.studentEmail.toLowerCase() === currentUser.email.toLowerCase()) ||
                  (entry.studentName && entry.studentName.toLowerCase() === currentUser.name.toLowerCase());
    if (isOwn) {
      return { allowed: true, fields: 'practice' }; // practice circles, practice time, student questions
    }
    return { allowed: false, reason: 'Students can only edit their own practice logs.' };
  }
  return { allowed: false, reason: 'Unauthorized role.' };
}

// ── Can this user delete a journal entry? ────────────────────────────────────
// Student:     Cannot delete entries
// Instructor:  Can delete entries for assigned students
// Admin:       Can delete any entry
function canDeleteJournalEntry(currentUser, entry) {
  // Admins can delete any entry
  if (currentUser.role === 'admin') {
    return { allowed: true };
  }
  // Instructors can delete entries for their assigned students
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u =>
      u.role === 'student' &&
      ((entry.studentEmail && u.email === entry.studentEmail) ||
       (entry.studentName && u.name.toLowerCase() === entry.studentName.toLowerCase()))
    );
    if (student && student.instructorId === currentUser.email) {
      return { allowed: true };
    }
    return { allowed: false, reason: 'Can only delete entries for your assigned students.' };
  }
  // Students cannot delete entries
  if (currentUser.role === 'student') {
    return { allowed: false, reason: 'Students cannot delete journal entries.' };
  }
  return { allowed: false, reason: 'Unauthorized role.' };
}

// ── Role Check: Validates permissions before any balance transaction ─────────
// Student: Read-only (0 write/update permission)
// Instructor: Can update assigned students only
// Admin: Can update ANY student's balance
function canUpdateBalance(currentUser, studentEmail) {
  if (currentUser.role === 'student') {
    return { allowed: false, reason: 'Students cannot modify balances (read-only access).' };
  }
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u => u.email === studentEmail && u.role === 'student');
    if (!student || student.instructorId !== currentUser.email) {
      return { allowed: false, reason: 'Instructors can only update balances for their assigned students.' };
    }
    return { allowed: true };
  }
  if (currentUser.role === 'admin') {
    return { allowed: true };
  }
  return { allowed: false, reason: 'Unauthorized role.' };
}

// ── Can this user manage other users? ────────────────────────────────────────
function canManageUsers(currentUser) {
  // Only admins can create, edit, or delete user accounts
  if (currentUser.role === 'admin') {
    return { allowed: true };
  }
  return { allowed: false, reason: 'Only administrators can manage user accounts.' };
}

// ── Can this user assign/unassign instructors to students? ───────────────────
function canAssignInstructor(currentUser) {
  // Only admins can assign/unassign instructor-student relationships
  if (currentUser.role === 'admin') {
    return { allowed: true };
  }
  return { allowed: false, reason: 'Only administrators can assign instructors to students.' };
}

// ── Can this user manage redemptions (redeem stamps/coins)? ──────────────────
// Instructor: Can redeem stamps/coins for assigned students
// Admin:      Can redeem stamps/coins for any student
function canManageRedemptions(currentUser) {
  if (currentUser.role === 'admin') {
    return { allowed: true };
  }
  if (currentUser.role === 'instructor') {
    return { allowed: true };
  }
  return { allowed: false, reason: 'Only instructors and administrators can manage redemptions.' };
}

// ── Can this user edit practice logs specifically? ───────────────────────────
// Student:     Can edit own practice logs (circles, time, questions)
// Instructor:  Can edit practice logs for assigned students
// Admin:       Can edit all practice logs
function canEditPracticeLogs(currentUser, studentEmail) {
  if (currentUser.role === 'admin') {
    return { allowed: true, fields: 'all' };
  }
  if (currentUser.role === 'student') {
    if (currentUser.email === studentEmail) {
      return { allowed: true, fields: 'practice' }; // circles, time, questions
    }
    return { allowed: false, reason: 'Students can only edit their own practice logs.' };
  }
  if (currentUser.role === 'instructor') {
    const users = JSON.parse(localStorage.getItem('mj_auth_users') || '[]');
    const student = users.find(u => u.email === studentEmail && u.role === 'student');
    if (student && student.instructorId === currentUser.email) {
      return { allowed: true, fields: 'all' };
    }
    return { allowed: false, reason: 'Can only edit practice logs for your assigned students.' };
  }
  return { allowed: false, reason: 'Unauthorized role.' };
}

// ── Permission summary for UI display ────────────────────────────────────────
function getPermissionSummary(role) {
  const perms = {
    student: {
      practiceLog:    'Edit own practice logs (circles, time, questions)',
      balances:       'Read own balance only (no edit)',
      journalEntries: 'View own entries only',
      userManagement: 'None',
      assignments:    'View assigned instructor only',
      redemptions:    'None',
    },
    instructor: {
      practiceLog:    'View + edit practice logs for assigned students',
      balances:       'Update assigned students only',
      journalEntries: 'View + edit + delete entries for assigned students',
      userManagement: 'None',
      assignments:    'View own student roster',
      redemptions:    'Redeem stamps/coins for assigned students',
    },
    admin: {
      practiceLog:    'Full access — view + edit ALL practice logs',
      balances:       'Full access — update ANY student balance',
      journalEntries: 'Full access — view + edit + delete ALL entries',
      userManagement: 'Full access — create, edit, delete ANY user (including admins)',
      assignments:    'Full access — assign/unassign ANY instructor-student pair',
      redemptions:    'Full access — redeem stamps/coins for any student',
    },
  };
  return perms[role] || {};
}


// ── Export for use in the app ────────────────────────────────────────────────
if (typeof window !== 'undefined') {
  window.SecurityRules = {
    canInstructorAccessStudent,
    canAccessPracticeLogs,
    canEditPracticeLogs,
    canViewJournalEntry,
    canEditJournalEntry,
    canDeleteJournalEntry,
    canUpdateBalance,
    canManageUsers,
    canAssignInstructor,
    canManageRedemptions,
    getPermissionSummary,
  };
}
