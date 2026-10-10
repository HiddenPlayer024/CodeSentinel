
import * as fs from 'fs';
import * as path from 'path';
export function readFile(filename: string) {
    const safePath = path.basename(filename);
    return fs.readFileSync('/var/www/html/' + safePath, 'utf8');
}
