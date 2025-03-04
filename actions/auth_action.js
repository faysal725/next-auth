"use server";

import { createAuthSession } from "@/lib/auth";
import { hashUserPassword } from "@/lib/hash";
import { createUser } from "@/user";
import { redirect } from "next/navigation";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");

  // validate the data
  let errors = {};

  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address.";
  }
  if (password.trim().length < 8) {
    errors.password = "Password must be at least 8 char long";
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors: errors,
    };
  }

  //   password hashing is done
  const hashedPassword = hashUserPassword(password);
  try {
    // store it in the db
    const userId = await createUser(email, hashedPassword);
    await createAuthSession(userId);
    redirect("/training");
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "email already exist.",
        },
      };
    }
    throw error;
  }
}
