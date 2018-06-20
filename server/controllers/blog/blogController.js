'use strict';
class BlogController {
    constructor() { }

    getBlogs(req, res) {
        res.status(200).json({
            blogs: [
                { name: 'medium' },
                { name: 'mdn' },
                { name: 'msdn' }
            ]
        });
    }
}

module.exports = new BlogController();
