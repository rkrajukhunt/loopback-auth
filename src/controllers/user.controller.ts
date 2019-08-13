import {
    Count,
    CountSchema,
    Filter,
    repository,
    Where,
} from '@loopback/repository';
import {
    post,
    param,
    get,
    getFilterSchemaFor,
    getModelSchemaRef,
    getWhereSchemaFor,
    patch,
    put,
    del,
    requestBody,
    HttpErrors,
} from '@loopback/rest';
import { User } from '../models';
import { UserRepository } from '../repositories';
import * as jwt from 'jsonwebtoken';
import { authenticate, AuthenticationBindings, UserProfile } from '@loopback/authentication'
import { inject } from '@loopback/core';

export class UserController {
    constructor(
        @repository(UserRepository)
        public userRepository: UserRepository,
        //@inject(AuthenticationBindings.CURRENT_USER) private currentUser: User
    ) { }

    @post('/users', {
        responses: {
            '200': {
                description: 'User model instance',
                content: { 'application/json': { schema: getModelSchemaRef(User) } },
            },
        },
    })
    async create(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(User, { exclude: ['id'] }),
                },
            },
        })
        user: Omit<User, 'id'>,
    ): Promise<any> {
        const countDoc = await this.userRepository.count();
        const { count } = countDoc;
        const id = count + 1;
        return this.userRepository.create({
            id,
            ...user,
        });
    }

    @post('/users/login')
    async login(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(User, {
                        exclude: ['name']
                    }),
                },
            },
        })
        user: Omit<User, 'id'>,
    ): Promise<any> {
        const {
            username,
            password,
        } = user;
        const userDoc = await this.userRepository.findOne({
            where: { username, password }
        });
        if (!userDoc) {
            throw new HttpErrors[400]('Invalid credentials');
        }
        const token = jwt.sign(userDoc.toJSON(), 'top');
        return {
            ...userDoc,
            token
        };
    }

    @authenticate('jwt')
    @get('/users/current')
    async printCurrentUser(
        @inject(AuthenticationBindings.CURRENT_USER) currentUserProfile: UserProfile,
    ): Promise<UserProfile> {
        return currentUserProfile;
    }

}
