import { db } from "@onecli/db";
import { APP_URL } from "../lib/env";

export const getProjectPublicUrl = async (
  projectId: string,
): Promise<string> => {
  const project = await db.project.findUnique({
    where: { id: projectId },
    select: { publicUrl: true },
  });

  return project?.publicUrl || APP_URL;
};

export const updateProjectPublicUrl = async (
  projectId: string,
  publicUrl: string | null,
): Promise<void> => {
  await db.project.update({
    where: { id: projectId },
    data: { publicUrl },
  });
};
