import { DISCORD_URL, GITHUB_URL } from "@/constants/constants";
import { useGetUserData, useUpdateUser } from "@/controllers/API/queries/auth";
import ModalsComponent from "@/pages/MainPage/components/modalsComponent";
import useFlowsManagerStore from "@/stores/flowsManagerStore";
import { Users } from "@/types/api";
import { FC, useEffect, useMemo, useState } from "react";

export const GetStartedProgress: FC<{
  userData: Users;
  isGithubStarred: boolean;
  isDiscordJoined: boolean;
  handleDismissDialog: () => void;
}> = ({ userData, isGithubStarred, isDiscordJoined, handleDismissDialog }) => {
  const [isGithubStarredChild, setIsGithubStarredChild] =
    useState(isGithubStarred);
  const [isDiscordJoinedChild, setIsDiscordJoinedChild] =
    useState(isDiscordJoined);
  const [newProjectModal, setNewProjectModal] = useState(false);

  const flows = useFlowsManagerStore((state) => state.flows);

  const { mutate: mutateLoggedUser } = useGetUserData();
  const { mutate: updateUser } = useUpdateUser();

  useEffect(() => {
    if (!userData) {
      mutateLoggedUser(null);
    }
  }, [userData, mutateLoggedUser]);

  const hasFlows = flows && flows?.length > 0;

  const percentageGetStarted = useMemo(() => {
    const stepValue = 33;
    let totalPercentage = 0;

    if (userData?.optins?.github_starred) {
      totalPercentage += stepValue;
    }

    if (userData?.optins?.discord_clicked) {
      totalPercentage += stepValue;
    }

    if (hasFlows) {
      totalPercentage += stepValue;
    }

    if (totalPercentage === 99) {
      return 100;
    }

    return Math.min(totalPercentage, 100);
  }, [userData?.optins, hasFlows]);

  const handleUserTrack = (key: string) => {
    const optins = userData?.optins ?? {};
    optins[key] = true;

    updateUser(
      {
        user_id: userData?.id!,
        user: { optins },
      },
      {
        onSuccess: () => {
          mutateLoggedUser({});
          if (key === "github_starred") {
            setIsGithubStarredChild(true);
            window.open(GITHUB_URL, "_blank", "noopener,noreferrer");
          } else if (key === "discord_clicked") {
            setIsDiscordJoinedChild(true);
            window.open(DISCORD_URL, "_blank", "noopener,noreferrer");
          } else if (key === "dialog_dismissed") {
            handleDismissDialog();
          }
        },
      },
    );
  };

  return (
    <ModalsComponent
      openModal={newProjectModal}
      setOpenModal={setNewProjectModal}
      openDeleteFolderModal={false}
      setOpenDeleteFolderModal={() => {}}
      handleDeleteFolder={() => {}}
    />
  );
};
