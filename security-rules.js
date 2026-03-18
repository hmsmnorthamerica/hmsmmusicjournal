// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE SECURITY RULES — Music Practice Journal
// Ensures an Instructor can only Read or Update a student document
// if the "instructorId" field in that document matches the Instructor's own uid.
// ═══════════════════════════════════════════════════════════════════════════════


// ─── OPTION A: FIRESTORE SECURITY RULES (firestore.rules) ────────────────────
// Copy the block below into your Firebase Console → Firestore → Rules tab.
//
// rules_version = '2';
// service cloud.firestore {
//   match /databases/{database}/documents {
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
//       // Admins have full access
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
//     // ── Practice logs ──────────────────────────────────────────────────────
//     match /students/{studentId}/practiceLogs/{logId} {
//
//       // Students can only read/write their own practice logs
//       allow read, write: if request.auth != null
//                          && request.auth.uid == studentId;
//
//       // Assigned instructor can read (not write) their student's logs
//       allow read: if request.auth != null
//                   && request.auth.token.role == 'instructor'
//                   && get(/databases/$(database)/documents/students/$(studentId)).data.instructorId == request.auth.uid;
//
//       // Admins have full access
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
//       // Admins have full access
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
//     }
//   }
// }


// ─── OPTION B: SUPABASE ROW LEVEL SECURITY (RLS) ────────────────────────────
// Run these SQL statements in your Supabase SQL Editor.
//
// -- Enable RLS on the students table
// ALTER TABLE students ENABLE ROW LEVEL SECURITY;
//
// -- Policy: Students can read/update only their own document
// CREATE POLICY "students_own_access"
//   ON students
//   FOR ALL
//   USING (auth.uid() = id)
//   WITH CHECK (auth.uid() = id);
//
// -- Policy: Instructors can READ a student document only if instructorId matches
// CREATE POLICY "instructor_read_assigned_students"
//   ON students
//   FOR SELECT
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   );
//
// -- Policy: Instructors can UPDATE a student document only if instructorId matches
// CREATE POLICY "instructor_update_assigned_students"
//   ON students
//   FOR UPDATE
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   )
//   WITH CHECK (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND instructor_id = auth.uid()
//   );
//
// -- Policy: Admins have full access
// CREATE POLICY "admin_full_access"
//   ON students
//   FOR ALL
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'admin'
//   );
//
// -- Enable RLS on practice_logs table
// ALTER TABLE practice_logs ENABLE ROW LEVEL SECURITY;
//
// -- Policy: Students can only see their own practice logs
// CREATE POLICY "students_own_logs"
//   ON practice_logs
//   FOR ALL
//   USING (auth.uid() = student_id)
//   WITH CHECK (auth.uid() = student_id);
//
// -- Policy: Instructors can read logs of their assigned students only
// CREATE POLICY "instructor_read_assigned_logs"
//   ON practice_logs
//   FOR SELECT
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   );
//
// -- Policy: Admins have full access to logs
// CREATE POLICY "admin_full_logs_access"
//   ON practice_logs
//   FOR ALL
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'admin'
//   );


// ─── FIRESTORE: Balance Transaction Rules ────────────────────────────────────
// Add these inside service cloud.firestore → match /databases/{database}/documents
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
//       // Admins can UPDATE balances for any student
//       allow read, write: if request.auth != null
//                          && request.auth.token.role == 'admin';
//
//       // Prevent negative balances
//       allow update: if request.resource.data.stamps >= 0
//                     && request.resource.data.coins >= 0;
//     }


// ─── SUPABASE: Balance Transaction RLS ───────────────────────────────────────
// Run these SQL statements in your Supabase SQL Editor.
//
// ALTER TABLE balances ENABLE ROW LEVEL SECURITY;
//
// -- Students: READ-only access to their own balance (zero write permission)
// CREATE POLICY "student_read_own_balance"
//   ON balances
//   FOR SELECT
//   USING (auth.uid() = student_id);
//
// -- Instructors: Can UPDATE balances only for their assigned students
// CREATE POLICY "instructor_update_assigned_balance"
//   ON balances
//   FOR UPDATE
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   )
//   WITH CHECK (
//     stamps >= 0 AND coins >= 0  -- prevent negative balances
//   );
//
// -- Instructors: Can READ balances for assigned students
// CREATE POLICY "instructor_read_assigned_balance"
//   ON balances
//   FOR SELECT
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'instructor'
//     AND student_id IN (
//       SELECT id FROM students WHERE instructor_id = auth.uid()
//     )
//   );
//
// -- Admins: Full access to all balances
// CREATE POLICY "admin_full_balance_access"
//   ON balances
//   FOR ALL
//   USING (
//     (SELECT role FROM profiles WHERE id = auth.uid()) = 'admin'
//   );


// ─── OPTION C: LOCAL SIMULATION (used in this app via localStorage) ──────────
// These functions mirror the Firestore/Supabase rules for our localStorage-based app.

function canInstructorAccessStudent(instructorEmail, studentData) {
  // Instructor can only read/update if the student's instructorId matches
  return studentData.instructorId === instructorEmail;
}

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
  // Admins can see all logs
  if (currentUser.role === 'admin') {
    return true;
  }
  return false;
}

// Role Check: Validates permissions before any balance transaction
// Student: Read-only (0 write/update permission)
// Instructor: Can update assigned students only
// Admin: Can update any student
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

// Export for use in the app
if (typeof window !== 'undefined') {
  window.SecurityRules = { canInstructorAccessStudent, canAccessPracticeLogs, canUpdateBalance };
}
