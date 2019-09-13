<?php

namespace App\Controller\Api;


use App\Entity\User;
use FOS\UserBundle\Model\UserManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * @Route("/auth")
 * Class ApiAuthController
 * @package App\Controller\Api
 */
class ApiAuthController extends AbstractController
{
    /**
     * @Route("/register", name="api_auth_register", methods={"POST"}))
     * @param Request $request
     * @param UserManagerInterface $usermanager
     * @return JsonResponse
     */
    public function register(Request $request, UserManagerInterface $usermanager)
    {
        $data = json_decode($request->getContent(), true);
        $validator = Validation::createValidator();
        $constraints = new Assert\Collection([
            'username' => new Assert\Length(['min' => 1]),
            'password' => new Assert\Length(['min' => 1]),
            'email' => new Assert\Email(),
        ]);

        $violations = $validator->validate($data, $constraints);
        if ($violations->count() > 0) {
            return new JsonResponse(['error' => (string)$violations], 500);
        }

        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];

        $user = new User;

        $user
            ->setUsername($username)
            ->setPlainPassword($password)
            ->setEmail($email)
            ->setEnabled(true)
            ->setRoles(['ROLE_USER'])
            ->setSuperAdmin(false);

        try {
            $usermanager->updateUser($user, true);
        } catch (\Exception $e) {
            return new JsonResponse(['error' => $e->getMessage()], 500);
        }
        return $this->redirectToRoute('api_auth_login',
            ['username' => $data['username'],
                'password' => $data['password'],
            ]. 307);
    }
}