<?php


namespace App\Security;


use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class UserVoter extends Voter
{
    const VIEW = 'view';
    const EDIT = 'edit';

    /**
     * @var AccessDecisionManagerInterface
     */
    private $decisionManager;

    public function __construct(AccessDecisionManagerInterface $decisionManager)
    {
        $this->decisionManager = $decisionManager;
    }

    protected function supports($attribute, $subject)
    {
        if (!in_array($attribute, [self::VIEW, self::EDIT])) {
            return false;
        }
        if (!$subject instanceof User) {
            return false;
        }
        return true;
    }

    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        if ($this->decisionManager->decide($token, ['ROLE_ADMIN'])) {
            return true;
        }
        /** @var USER $userSubject */
        $userSubject = $subject;

        switch ($attribute) {
            case self::VIEW:
                return $this->canView($userSubject, $user);
            case self::EDIT:
                return $this->canEdit($userSubject, $user);
        }
        throw new \LogicException('This code should not be reached!');
    }

    private function canView($userSubject, $user)
    {
        if ($this->canEdit($userSubject, $user)) {
            return true;
        }
        return $user === $userSubject;
    }

    private function canEdit($userSubject, $user)
    {
        return $user === $userSubject;
    }
}