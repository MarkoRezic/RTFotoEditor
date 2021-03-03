import { useState, useEffect, useContext } from 'react';
import Axios from 'axios';
import { Image } from 'cloudinary-react';
import { AuthorityContext } from './AuthorityContext';
import { NavLink } from 'react-router-dom';

const Posts = () => {
    // eslint-disable-next-line
    const [userList, setUserList, currentUser, setCurrentUser] = useContext(AuthorityContext);
    Axios.defaults.withCredentials = true;
    let url = 'https://rt-foto-editor.herokuapp.com';
    //let url = 'http://localhost:3001';

    const [posts, setPosts] = useState();
    const [isLoading, setIsLoading] = useState(true);
    const loadImages = () => {
        Axios.get(url + '/posts/public').then((response) => {
            setPosts(response.data.sort(function(a,b){
                return b.id - a.id;
            }));
            setIsLoading(false);
        });
    };
    useEffect(() => {
        loadImages();
        // eslint-disable-next-line
    }, [currentUser]);

    return (
        <div>
            <div className="blog-header small-header">
                <div className="container btrans small-btrans">
                    <h1 className="text-center"><strong> Posts</strong></h1>
                </div>
            </div>

            <div className="container">

                <div className="row">

                    <div className="col-sm-12 blog-main">

                        <div className="blog-post Posts">
                            <hr className="round" />
                            <div className="centeredContainer">
                                {isLoading ?
                                    <div className="lds-spinner"><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div></div>
                                    : posts ?
                                        posts.map((post) => (
                                            <div className="postContainer" key={post.id}>
                                                <p className="postContainerP">{post.displayname}</p>
                                                <NavLink to={'/posts/' + post.id} className="postThumbnailContainer">
                                                    <Image
                                                        cloudName={'rt-foto-editor'}
                                                        publicId={post.public_id}
                                                        width="300"
                                                        crop="scale"
                                                        className="postThumbnailImage"
                                                    />
                                                </NavLink>
                                            </div>
                                        ))
                                        : null}
                            </div>
                            <hr className="round" />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Posts;