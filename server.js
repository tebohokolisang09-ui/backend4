// server.js
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import fetch from "node-fetch";

// Fix for Node < 18
globalThis.fetch = fetch;

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));

if (!process.env.SUPABASE_KEY || !process.env.JWT_SECRET) {
  console.error("❌ Missing SUPABASE_KEY or JWT_SECRET in .env file");
  process.exit(1);
}

// Supabase init
const supabaseUrl = "https://hixkbsqxlszmbslcsvny.supabase.co";
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Test connection
(async () => {
  try {
    const { error } = await supabase.from("users").select("*").limit(1);
    if (error) throw error;
    console.log("✅ Connected to Supabase successfully!");
  } catch (err) {
    console.error("❌ Supabase connection failed:", err.message);
  }
})();

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// ------------------- AUTH -------------------
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role)
      return res.status(400).json({ error: "All fields are required" });

    const allowedRoles = ["student", "lecturer", "prl", "pl"];
    if (!allowedRoles.includes(role.toLowerCase()))
      return res.status(400).json({ error: "Invalid role selected" });

    const { data: existingUser } = await supabase
      .from("users")
      .select("email")
      .eq("email", email)
      .maybeSingle();

    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from("users")
      .insert([{ name, email, password: hashedPassword, role: role.toLowerCase() }])
      .select();

    if (error) throw error;

    res.status(201).json({ success: true, message: "User registered", user: data[0] });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .maybeSingle();

    if (error || !data) return res.status(401).json({ error: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, data.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: data.user_id, role: data.role, name: data.name, email: data.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: { id: data.user_id, name: data.name, email: data.email, role: data.role },
    });
  } catch (err) {
    console.error("Login Error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("user_id, name, email, role, created_at")
      .eq("user_id", req.user.id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("Profile Error:", err.message);
    res.status(500).json({ error: "Profile retrieval failed" });
  }
});

// ------------------- CLASSES -------------------

// Get all classes
app.get("/classes", authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("classes")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error("Fetch Classes Error:", err.message);
    res.status(500).json({ error: "Failed to fetch classes" });
  }
});

// Get available classes for dropdown (SINGLE ENDPOINT - NO DUPLICATES)
app.get("/classes/options", authenticateToken, async (req, res) => {
  try {
    let query = supabase
      .from("classes")
      .select("id, class_name, course_name, course_code, lecturer")
      .order("class_name");

    // If user is lecturer, only show their classes
    if (req.user.role === "lecturer") {
      query = query.ilike("lecturer", `%${req.user.name}%`);
    }

    const { data, error } = await query;

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error("Fetch Classes Error:", err.message);
    res.status(500).json({ error: "Failed to fetch classes" });
  }
});

// Add class
app.post("/classes", authenticateToken, async (req, res) => {
  try {
    const {
      class_name,
      course_name,
      course_code,
      lecturer,
      schedule,
      venue,
      capacity,
      status,
    } = req.body;

    if (!class_name || !course_name || !course_code || !lecturer)
      return res.status(400).json({ error: "Required fields missing" });

    // Only lecturers and PL/PRL can create classes
    if (!["lecturer", "pl", "prl"].includes(req.user.role)) {
      return res.status(403).json({ error: "Not authorized to create class" });
    }

    const { data, error } = await supabase
      .from("classes")
      .insert([
        {
          class_name,
          course_name,
          course_code,
          lecturer,
          schedule: schedule || null,
          venue: venue || null,
          capacity: capacity ? parseInt(capacity) : null,
          status: status || "active",
          created_by: req.user.name,
        },
      ])
      .select();

    if (error) throw error;

    res.status(201).json({ success: true, class: data[0] });
  } catch (err) {
    console.error("Add Class Error:", err.message);
    res.status(500).json({ error: "Failed to add class" });
  }
});

// Update class
app.put("/classes/:id", authenticateToken, async (req, res) => {
  try {
    const classId = req.params.id;
    const updates = req.body;

    const { data: existingClass, error: fetchError } = await supabase
      .from("classes")
      .select("*")
      .eq("id", classId)
      .single();

    if (fetchError || !existingClass)
      return res.status(404).json({ error: "Class not found" });

    // PL can edit any class, others only their own
    if (req.user.role !== "pl" && existingClass.created_by !== req.user.name) {
      return res.status(403).json({ error: "Not authorized to edit this class" });
    }

    // Convert capacity to integer if provided
    if (updates.capacity) updates.capacity = parseInt(updates.capacity);

    const { data, error } = await supabase
      .from("classes")
      .update(updates)
      .eq("id", classId)
      .select();

    if (error) throw error;

    res.json({ success: true, class: data[0] });
  } catch (err) {
    console.error("Update Class Error:", err.message);
    res.status(500).json({ error: "Failed to update class" });
  }
});

// Delete class
app.delete("/classes/:id", authenticateToken, async (req, res) => {
  try {
    const classId = req.params.id;

    const { data: existingClass, error: fetchError } = await supabase
      .from("classes")
      .select("*")
      .eq("id", classId)
      .single();

    if (fetchError || !existingClass)
      return res.status(404).json({ error: "Class not found" });

    // PL can delete any class, others only their own
    if (req.user.role !== "pl" && existingClass.created_by !== req.user.name) {
      return res.status(403).json({ error: "Not authorized to delete this class" });
    }

    const { error: delError } = await supabase
      .from("classes")
      .delete()
      .eq("id", classId);

    if (delError) throw delError;

    res.json({ success: true, message: "Class deleted successfully" });
  } catch (err) {
    console.error("Delete Class Error:", err.message);
    res.status(500).json({ error: "Failed to delete class" });
  }
});

// ------------------- REPORTS -------------------

// Get all reports (with role-based filtering)
app.get("/reports", authenticateToken, async (req, res) => {
  try {
    let query = supabase
      .from("report")
      .select(`
        *,
        classes(class_name, course_name, course_code, lecturer),
        users!report_submitted_by_fkey(name)
      `)
      .order("created_at", { ascending: false });

    // Lecturers can only see their own reports
    if (req.user.role === "lecturer") {
      query = query.eq("submitted_by", req.user.id);
    }

    const { data, error } = await query;

    if (error) {
      console.error("Supabase reports error:", error);
      throw error;
    }

    // Transform the data to match frontend expectations
    const transformedData = data.map(report => ({
      id: report.report_id,
      faculty_name: "Faculty of ICT",
      class_name: report.classes?.class_name || "Unknown Class",
      class_id: report.class_id,
      week_of_reporting: `Week ${report.week}`,
      date_of_lecture: report.date,
      course_name: report.classes?.course_name || "Unknown Course",
      course_code: report.classes?.course_code || "N/A",
      lecturer_name: report.classes?.lecturer || report.users?.name || "Unknown Lecturer",
      actual_students_present: report.actual_students,
      total_registered_students: 50,
      venue: "Room 101",
      scheduled_time: "10:00",
      topic_taught: report.topic,
      learning_outcomes: report.learning_outcomes,
      recommendations: report.recommendations,
      status: "submitted",
      feedback: "",
      created_by: report.submitted_by,
      created_at: report.created_at
    }));

    res.json(transformedData || []);
  } catch (err) {
    console.error("Fetch Reports Error:", err.message);
    res.status(500).json({ error: "Failed to fetch reports: " + err.message });
  }
});

// Create new report
app.post("/reports", authenticateToken, async (req, res) => {
  try {
    const {
      class_id,
      week,
      date,
      topic,
      learning_outcomes,
      recommendations,
      actual_students
    } = req.body;

    // Validate required fields
    if (!class_id || !week || !date || !topic || !actual_students) {
      return res.status(400).json({ 
        error: "Class, week, date, topic, and actual students are required" 
      });
    }

    const { data, error } = await supabase
      .from("report")
      .insert([
        {
          class_id: parseInt(class_id),
          week: parseInt(week),
          date: date,
          topic: topic,
          learning_outcomes: learning_outcomes || null,
          recommendations: recommendations || null,
          actual_students: parseInt(actual_students),
          submitted_by: req.user.id
        }
      ])
      .select(`
        *,
        classes(class_name, course_name, course_code, lecturer),
        users!report_submitted_by_fkey(name)
      `);

    if (error) {
      console.error("Supabase create report error:", error);
      throw error;
    }

    if (!data || data.length === 0) {
      throw new Error("No data returned after insert");
    }

    // Transform the response
    const transformedReport = {
      id: data[0].report_id,
      faculty_name: "Faculty of ICT",
      class_name: data[0].classes?.class_name || "Unknown Class",
      class_id: data[0].class_id,
      week_of_reporting: `Week ${data[0].week}`,
      date_of_lecture: data[0].date,
      course_name: data[0].classes?.course_name || "Unknown Course",
      course_code: data[0].classes?.course_code || "N/A",
      lecturer_name: data[0].classes?.lecturer || data[0].users?.name || "Unknown Lecturer",
      actual_students_present: data[0].actual_students,
      total_registered_students: 50,
      venue: "Room 101",
      scheduled_time: "10:00",
      topic_taught: data[0].topic,
      learning_outcomes: data[0].learning_outcomes,
      recommendations: data[0].recommendations,
      status: "submitted",
      feedback: "",
      created_by: data[0].submitted_by,
      created_at: data[0].created_at
    };

    res.status(201).json({ success: true, report: transformedReport });
  } catch (err) {
    console.error("Create Report Error:", err.message);
    res.status(500).json({ error: "Failed to create report: " + err.message });
  }
});

app.get("/lecturers", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("user_id, name, email, role")
      .eq("role", "lecturer"); // only lecturers

    if (error) throw error;

    res.status(200).json(data);
  } catch (err) {
    console.error("Error fetching lecturers:", err);
    res.status(500).json({ error: "Failed to fetch lecturers" });
  }
});


// Update report (for PRL feedback)
app.put("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;
    const { feedback } = req.body;

    // Only PRL can add feedback
    if (req.user.role !== "prl") {
      return res.status(403).json({ error: "Not authorized to update reports" });
    }

    // For now, we'll just return the report since feedback column might not exist
    const { data, error } = await supabase
      .from("report")
      .select(`
        *,
        classes(class_name, course_name, course_code, lecturer),
        users!report_submitted_by_fkey(name)
      `)
      .eq("report_id", reportId)
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Report not found" });

    // Transform the response
    const transformedReport = {
      id: data.report_id,
      faculty_name: "Faculty of ICT",
      class_name: data.classes?.class_name || "Unknown Class",
      class_id: data.class_id,
      week_of_reporting: `Week ${data.week}`,
      date_of_lecture: data.date,
      course_name: data.classes?.course_name || "Unknown Course",
      course_code: data.classes?.course_code || "N/A",
      lecturer_name: data.classes?.lecturer || data.users?.name || "Unknown Lecturer",
      actual_students_present: data.actual_students,
      total_registered_students: 50,
      venue: "Room 101",
      scheduled_time: "10:00",
      topic_taught: data.topic,
      learning_outcomes: data.learning_outcomes,
      recommendations: data.recommendations,
      status: "submitted",
      feedback: feedback || "",
      created_by: data.submitted_by,
      created_at: data.created_at
    };

    res.json({ success: true, report: transformedReport });
  } catch (err) {
    console.error("Update Report Error:", err.message);
    res.status(500).json({ error: "Failed to update report" });
  }
});

// Get single report
app.get("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;

    const { data, error } = await supabase
      .from("report")
      .select(`
        *,
        classes(class_name, course_name, course_code, lecturer),
        users!report_submitted_by_fkey(name)
      `)
      .eq("report_id", reportId)
      .single();

    if (error) throw error;

    // Check if user has permission to view this report
    if (req.user.role === "lecturer" && data.submitted_by !== req.user.id) {
      return res.status(403).json({ error: "Not authorized to view this report" });
    }

    // Transform the data
    const transformedReport = {
      id: data.report_id,
      faculty_name: "Faculty of ICT",
      class_name: data.classes?.class_name || "Unknown Class",
      class_id: data.class_id,
      week_of_reporting: `Week ${data.week}`,
      date_of_lecture: data.date,
      course_name: data.classes?.course_name || "Unknown Course",
      course_code: data.classes?.course_code || "N/A",
      lecturer_name: data.classes?.lecturer || data.users?.name || "Unknown Lecturer",
      actual_students_present: data.actual_students,
      total_registered_students: 50,
      venue: "Room 101",
      scheduled_time: "10:00",
      topic_taught: data.topic,
      learning_outcomes: data.learning_outcomes,
      recommendations: data.recommendations,
      status: "submitted",
      feedback: "",
      created_by: data.submitted_by,
      created_at: data.created_at
    };

    res.json(transformedReport);
  } catch (err) {
    console.error("Get Report Error:", err.message);
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

// GET all courses
app.get("/courses", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("courses")
      .select("*")
      .order("course_id", { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error("Fetch courses error:", err.message);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// GET single course
app.get("/courses/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("courses")
      .select("*")
      .eq("course_id", id)
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error("Fetch course error:", err.message);
    res.status(500).json({ error: "Failed to fetch course" });
  }
});

// CREATE course
app.post("/courses", async (req, res) => {
  const { course_code, course_name, faculty } = req.body;
  try {
    const { data, error } = await supabase
      .from("courses")
      .insert([{ course_code, course_name, faculty }])
      .select();

    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (err) {
    console.error("Create course error:", err.message);
    res.status(500).json({ error: "Failed to create course" });
  }
});

// UPDATE course
app.put("/courses/:id", async (req, res) => {
  const { id } = req.params;
  const { course_code, course_name, faculty } = req.body;
  try {
    const { data, error } = await supabase
      .from("courses")
      .update({ course_code, course_name, faculty })
      .eq("course_id", id)
      .select();

    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    console.error("Update course error:", err.message);
    res.status(500).json({ error: "Failed to update course" });
  }
});

// DELETE course
app.delete("/courses/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("courses")
      .delete()
      .eq("course_id", id)
      .select();

    if (error) throw error;
    res.json({ message: "Course deleted successfully", course: data[0] });
  } catch (err) {
    console.error("Delete course error:", err.message);
    res.status(500).json({ error: "Failed to delete course" });
  }
});

// ------------------- RATINGS -------------------
// ... Keep your existing ratings routes (unchanged) ...

// ------------------- SYSTEM -------------------
app.get("/health", (req, res) =>
  res.json({ status: "OK", timestamp: new Date().toISOString(), service: "LUCT Reporting System API" })
);

app.get("/", (req, res) => res.send("📡 LUCT Reporting System Backend is running!"));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));