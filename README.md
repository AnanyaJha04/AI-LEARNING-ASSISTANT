# AI-LEARNING ASSISTANT
This is a model for an AI-based learning assistant that students and teachers can use to assist themselves in a personalized way.
For Students:
1. Personalized Learning Paths
2. Adaptive Assessments
3. AI-based Analysis and Feedback
4. Personalized study materials
For Teachers:
1. Monitor Student’s Progress
2. Personalized teaching and reference materials
3. AI-generated teaching plan for creative teaching

To make learning secure, there is a crucial need to implement various security techniques to safeguard sensitive data, AI models, network infrastructure, etc.
There are multiple ways to achieve it, starting from basic techniques like Authentication, Verification, Firewalls, and Traffic Analysis to complicated models like SIEM and IDPS.
Here, we would try to implement some of the mitigation techniques.

# AUTHENTICATION AND AUTHORIZATION
Authentication is the process of verifying a user's identity before granting them access to a system or resource.
Authorization is the process of granting a person or entity permission to access or use a specific resource, system, or service.

## Purpose-
Allow users to set up a username, password, designation, and a random security question. Once set, they would be asked to log in in 2 steps. In the first step, they would be asked to enter their username, password, and designation. If the credentials get verified, they are redirected to the second step, where they answer the security question; if verified, they will be granted access.

## Features-
1. 2-Way Authentication
2. Password Verification
3. Security Question is easy to remember, yet hard to guess

## Further Improvement- 
1. Password checker- Embed a code for a password checker to ensure the entered password is strong.
2. Improvised question- Make the security question harder to guess.
3. OTP- We can make a model to generate OTPs for more secure access.
4. Multi Factor authentication
