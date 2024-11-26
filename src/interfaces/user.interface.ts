export interface User {
  id: string;
  cognitoSub: string;
  email?: string;
  mobile?: string;
  username: string;
  displayName: string;
  dateOfBirth: Date;
  createdAt: Date;
  updatedAt: Date;
}
